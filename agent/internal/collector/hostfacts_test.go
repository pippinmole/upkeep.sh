package collector

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestCollectLocalUsers(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/passwd": unit(`root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
# a comment
+nisuser::::::
alice:x:1000:1000:Alice,,,:/home/alice:/bin/zsh
bob:x:1001:1001::/home/bob:
svc:x:998:998::/var/lib/svc:/bin/false
alice:x:1002:1002:dup:/home/alice2:/bin/sh
broken:x:notanumber:1::/:/bin/sh
`),
		"etc/group": unit(`root:x:0:
daemon:x:1:
adm:x:4:syslog,alice
sudo:x:27:alice
docker:x:999:alice,bob
alice:x:1000:
bob:x:1001:
svc:x:998:
`),
	}
	users, truncated, err := CollectLocalUsers(fsys)
	if err != nil || truncated {
		t.Fatalf("err=%v truncated=%v", err, truncated)
	}
	want := []User{
		{
			Name: "alice", UID: 1000, GID: 1000, Home: "/home/alice", Shell: "/bin/zsh",
			Groups: []string{"alice", "adm", "docker", "sudo"}, LoginShell: true, Admin: true,
		},
		{
			Name: "bob", UID: 1001, GID: 1001, Home: "/home/bob",
			Groups: []string{"bob", "docker"}, LoginShell: true,
		}, // empty shell = /bin/sh
		{Name: "daemon", UID: 1, GID: 1, Home: "/usr/sbin", Shell: "/usr/sbin/nologin", Groups: []string{"daemon"}},
		{Name: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash", Groups: []string{"root"}, LoginShell: true, Admin: true},
		{Name: "svc", UID: 998, GID: 998, Home: "/var/lib/svc", Shell: "/bin/false", Groups: []string{"svc"}},
	}
	if !reflect.DeepEqual(users, want) {
		t.Errorf("users:\n got %+v\nwant %+v", users, want)
	}

	if _, _, err := CollectLocalUsers(fstest.MapFS{"etc/passwd": unit("root:x:0:0::/root:/bin/sh\n")}); err == nil {
		t.Error("missing etc/group: want error")
	}
}

func TestCollectLocalUsersCap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxUsers+1; i++ {
		fmt.Fprintf(&b, "u%05d:x:%d:100::/home/u:/bin/sh\n", i, 2000+i)
	}
	users, truncated, err := CollectLocalUsers(fstest.MapFS{"etc/passwd": unit(b.String()), "etc/group": unit("")})
	if err != nil || !truncated || len(users) != MaxUsers {
		t.Errorf("err=%v truncated=%v n=%d", err, truncated, len(users))
	}
}

const (
	mapsWithDeleted = `55d0c0a00000-55d0c0a2e000 r--p 00000000 fd:01 1310 /usr/sbin/sshd
7f1c2e000000-7f1c2e200000 r-xp 00000000 fd:01 2001 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)
7f1c2e200000-7f1c2e400000 r--p 00200000 fd:01 2001 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)
7f1c2e400000-7f1c2e600000 r-xp 00000000 fd:01 2002 /usr/lib/x86_64-linux-gnu/libcrypto.so.3 (deleted)
7f1c2e600000-7f1c2e800000 rw-s 00000000 00:01 2003 /memfd:pulseaudio (deleted)
7f1c2e800000-7f1c2ea00000 rw-s 00000000 00:05 2004 /dev/shm/foo (deleted)
7f1c2ea00000-7f1c2ec00000 rw-p 00000000 fd:01 2005 /tmp/some file (deleted)
7f1c2ec00000-7f1c2ee00000 r-xp 00000000 fd:01 2006 /opt/my app/lib/libapp.so (deleted)
7ffd0f3e1000-7ffd0f402000 rw-p 00000000 00:00 0 [stack]
`
	mapsClean = `55d0c0a00000-55d0c0a2e000 r--p 00000000 fd:01 1310 /usr/sbin/cron
7f1c2e000000-7f1c2e200000 r-xp 00000000 fd:01 2010 /usr/lib/x86_64-linux-gnu/libc.so.6
`
)

func TestCollectDeletedLibs(t *testing.T) {
	p := newFakeProc(t)
	p.process("812", "sshd", "0::/system.slice/ssh.service\n", mapsWithDeleted)
	p.process("900", "cron", "0::/system.slice/cron.service\n", mapsClean)
	p.process("950", "python3", "0::/user.slice/user-1000.slice/session-3.scope\n",
		"7f1c2e000000-7f1c2e200000 r-xp 00000000 fd:01 2001 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)\n")
	p.process("960", "postgres", "0::/system.slice/postgresql@15-main.service\n", mapsWithDeleted)
	// Another user's process: maps unreadable without CAP_SYS_PTRACE.
	if err := os.Chmod(filepath.Join(p.root, "960", "maps"), 0); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Log("running as root: the unreadable-maps case can't be simulated")
	}
	p.file("1/comm", "kthreadd\n") // no maps file: exited or kernel thread, skipped

	units := ProcessUnits(p.root)
	got, err := CollectDeletedLibs(p.root, units)
	if err != nil {
		t.Fatal(err)
	}
	want := NeedsRestart{
		Processes: []DeletedLibProcess{
			{PID: 812, Name: "sshd", Unit: "ssh.service", Libraries: []string{
				"/opt/my app/lib/libapp.so",
				"/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
				"/usr/lib/x86_64-linux-gnu/libssl.so.3",
			}},
			{PID: 950, Name: "python3", Libraries: []string{"/usr/lib/x86_64-linux-gnu/libssl.so.3"}},
		},
		UnreadableProcesses: 1,
	}
	if os.Geteuid() == 0 {
		want.Processes = append(want.Processes, DeletedLibProcess{
			PID: 960, Name: "postgres",
			Unit: "postgresql@15-main.service", Libraries: want.Processes[0].Libraries,
		})
		want.UnreadableProcesses = 0
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}

	if _, err := CollectDeletedLibs(filepath.Join(p.root, "missing"), nil); err == nil {
		t.Error("missing procfs: want error")
	}
}

func TestCollectDeletedLibsCaps(t *testing.T) {
	p := newFakeProc(t)
	var maps strings.Builder
	for i := 0; i < MaxDeletedLibsPerProcess+5; i++ {
		fmt.Fprintf(&maps, "7f00-7f01 r-xp 00000000 fd:01 %d /usr/lib/lib%03d.so.1 (deleted)\n", i, i)
	}
	for pid := 1; pid <= MaxDeletedLibProcesses+2; pid++ {
		p.process(fmt.Sprint(pid), "p", "", maps.String())
	}
	got, err := CollectDeletedLibs(p.root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Truncated || len(got.Processes) != MaxDeletedLibProcesses ||
		len(got.Processes[0].Libraries) != MaxDeletedLibsPerProcess || got.Processes[0].PID != 1 {
		t.Errorf("truncated=%v processes=%d libs=%d", got.Truncated, len(got.Processes), len(got.Processes[0].Libraries))
	}
}

func TestCollectUnattendedUpgrades(t *testing.T) {
	stamp := time.Date(2026, 9, 26, 6, 12, 0, 0, time.UTC)
	lists := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	run := time.Date(2026, 9, 26, 6, 30, 0, 0, time.UTC)
	fsys := fstest.MapFS{
		"etc/apt/apt.conf.d/10periodic": unit(`APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";`),
		"etc/apt/apt.conf.d/20auto-upgrades": unit(`// written by dpkg-reconfigure
APT::Periodic::Update-Package-Lists "1";
/* multi
   line */ APT::Periodic::Unattended-Upgrade "1";
`),
		"etc/apt/apt.conf.d/50unattended-upgrades": unit(`Unattended-Upgrade::Allowed-Origins {
	"${distro_id}:${distro_codename}-security";
};
`),
		"etc/apt/apt.conf.d/99off.dpkg-old":              unit(`APT::Periodic::Unattended-Upgrade "0";`),
		"var/lib/apt/periodic/update-success-stamp":      {ModTime: stamp},
		"var/lib/apt/lists/lock":                         {},
		"var/lib/apt/lists":                              {Mode: 0o755 | os.ModeDir, ModTime: lists},
		"var/lib/apt/periodic/unattended-upgrades-stamp": {ModTime: run},
	}
	pkgs := []Package{{Name: "unattended-upgrades", Ecosystem: "deb"}}
	got, err := CollectUnattendedUpgrades(fsys, pkgs)
	if err != nil {
		t.Fatal(err)
	}
	yes := true
	want := UnattendedUpgrades{
		PackageInstalled: &yes, UpdatePackageLists: "1", UnattendedUpgrade: "1", Enabled: true,
		LastAptUpdate: "2026-09-26T06:12:00Z", LastAptUpdateSource: "update-success-stamp",
		LastUnattendedRun: "2026-09-26T06:30:00Z",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}

	// Package missing: configured but not enabled. No stamp: lists mtime.
	delete(fsys, "var/lib/apt/periodic/update-success-stamp")
	got, _ = CollectUnattendedUpgrades(fsys, []Package{})
	if got.Enabled || got.PackageInstalled == nil || *got.PackageInstalled ||
		got.LastAptUpdateSource != "lists" || got.LastAptUpdate != "2026-09-25T00:00:00Z" {
		t.Errorf("package missing: %+v", got)
	}

	// Nothing configured, inventory unknown.
	got, err = CollectUnattendedUpgrades(fstest.MapFS{"var/lib/apt": {Mode: 0o755 | os.ModeDir}}, nil)
	if err != nil || got.Enabled || got.PackageInstalled != nil || got.LastAptUpdate != "" {
		t.Errorf("empty host: %+v, %v", got, err)
	}

	// No var/lib/apt at all on an apt host: not visible (e.g. a separate
	// /var the agent's mounts don't carry), an error, not empty facts.
	if _, err = CollectUnattendedUpgrades(fstest.MapFS{}, nil); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("no var/lib/apt: err = %v, want ErrNotExist", err)
	}
}

func TestCollectUptime(t *testing.T) {
	p := newFakeProc(t)
	p.file("uptime", "350735.47 234388.90\n")
	if got, err := CollectUptime(os.DirFS(p.root)); err != nil || got != 350735 {
		t.Errorf("uptime = %d, %v", got, err)
	}
	for _, bad := range []string{"", "abc 1", "-5 1"} {
		p.file("uptime", bad)
		if _, err := CollectUptime(os.DirFS(p.root)); err == nil {
			t.Errorf("uptime %q: want error", bad)
		}
	}
}

func TestCollectArch(t *testing.T) {
	p := newFakeProc(t)
	p.file("sys/kernel/arch", "aarch64\n")
	dpkg := []Package{{Name: "libc6", Arch: "amd64", Ecosystem: "deb"}, {Name: "dpkg", Arch: "armhf", Ecosystem: "deb"}}
	if got, err := CollectArch(dpkg, os.DirFS(p.root)); err != nil || got != "armhf" {
		t.Errorf("from dpkg = %q, %v (want armhf: userland over kernel)", got, err)
	}
	if got, err := CollectArch(nil, os.DirFS(p.root)); err != nil || got != "arm64" {
		t.Errorf("from kernel = %q, %v", got, err)
	}
	if _, err := CollectArch(nil, nil); err == nil {
		t.Error("no source: want error")
	}
	if _, err := CollectArch(nil, os.DirFS(t.TempDir())); err == nil {
		t.Error("no arch file: want error")
	}
}
