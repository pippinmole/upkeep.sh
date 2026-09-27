package collector

import (
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"testing"
	"testing/fstest"
)

func link(target string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte(target), Mode: fs.ModeSymlink | 0o777}
}

func unit(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }

// A Debian-like host: vendor units in lib/, admin enablement and masks in
// etc/, a drop-in, a template with instances, and socket activation.
func systemdHost() fstest.MapFS {
	return fstest.MapFS{
		"lib/systemd/system/ssh.service": unit(`[Unit]
Description=OpenBSD Secure Shell server
[Service]
ExecStartPre=/usr/sbin/sshd -t
ExecStart=/usr/sbin/sshd -D $SSHD_OPTS
[Install]
WantedBy=multi-user.target
Alias=sshd.service
`),
		"lib/systemd/system/cron.service": unit(`[Unit]
Description=Regular background program processing daemon
[Service]
ExecStart=/usr/sbin/cron -f $EXTRA_OPTS
[Install]
WantedBy=multi-user.target
`),
		"lib/systemd/system/postgresql@.service": unit(`[Unit]
Description=PostgreSQL Cluster %i
[Service]
User=postgres
ExecStart=-/usr/bin/pg_ctlcluster --skip-systemctl-redirect %i start
[Install]
WantedBy=multi-user.target
`),
		"lib/systemd/system/systemd-journald.service": unit(`[Unit]
Description=Journal Service
[Service]
ExecStart=/lib/systemd/systemd-journald
`),
		"lib/systemd/system/sysinit.target.wants/systemd-journald.service": link("../systemd-journald.service"),
		"lib/systemd/system/systemd-fsck@.service":                         unit("[Unit]\nDescription=File System Check on %f\n[Service]\nExecStart=/lib/systemd/systemd-fsck %f\n"),
		"lib/systemd/system/cups.service": unit(`[Unit]
Description=CUPS Scheduler
[Service]
ExecStart=/usr/sbin/cupsd -l
[Install]
Also=cups.socket
`),
		"lib/systemd/system/cups.socket":       unit("[Socket]\nListenStream=/run/cups/cups.sock\n[Install]\nWantedBy=sockets.target\n"),
		"lib/systemd/system/apt-daily.service": unit("[Unit]\nDescription=Daily apt download activities\n[Service]\nType=oneshot\nExecStart=/usr/lib/apt/apt.systemd.daily update\n"),
		"lib/systemd/system/apt-daily.timer":   unit("[Timer]\nOnCalendar=*-*-* 6,18:00\n[Install]\nWantedBy=timers.target\n"),
		"lib/systemd/system/snapd.service":     unit("[Service]\nExecStart=/usr/lib/snapd/snapd\n[Install]\nWantedBy=multi-user.target\n"),
		"lib/systemd/system/nginx.service": unit(`[Unit]
Description=A high performance web server
[Service]
ExecStart=/usr/sbin/nginx -g 'daemon on;'
[Install]
WantedBy=multi-user.target
`),
		"lib/systemd/system/dyn.service":          unit("[Service]\nDynamicUser=yes\nExecStart=\"/opt/my app/bin\" --flag\n[Install]\nWantedBy=multi-user.target\n"),
		"lib/systemd/system/empty-masked.service": unit(""),

		// Admin state in /etc.
		"etc/systemd/system/sshd.service":                                       link("/lib/systemd/system/ssh.service"), // alias
		"etc/systemd/system/multi-user.target.wants/ssh.service":                link("/lib/systemd/system/ssh.service"),
		"etc/systemd/system/multi-user.target.wants/cron.service":               link("/lib/systemd/system/cron.service"),
		"etc/systemd/system/multi-user.target.wants/postgresql@15-main.service": link("/lib/systemd/system/postgresql@.service"),
		"etc/systemd/system/sockets.target.wants/cups.socket":                   link("/lib/systemd/system/cups.socket"),
		"etc/systemd/system/timers.target.wants/apt-daily.timer":                link("/lib/systemd/system/apt-daily.timer"),
		"etc/systemd/system/snapd.service":                                      link("/dev/null"), // masked
		"etc/systemd/system/cron.service.d/override.conf":                       unit("[Service]\nUser=nobody\n"),
		"etc/systemd/system/nginx.service.d/10-exec.conf":                       unit("[Service]\nExecStart=\nExecStart=/opt/nginx/sbin/nginx -g 'daemon off;'\n"),
		"etc/systemd/system/nginx.service.d/20-user.conf":                       unit("[Service]\nUser=www-data\n[Install]\nWantedBy=nothing.target\n"),
		"etc/systemd/system/custom.service":                                     link("/opt/custom/custom.service"), // linked unit
		"opt/custom/custom.service":                                             unit("[Unit]\nDescription=Custom\n[Service]\nExecStart=/opt/custom/bin/custom\n"),
	}
}

func TestCollectSystemdServices(t *testing.T) {
	running := map[int]string{
		100: "ssh.service", 101: "ssh.service",
		200: "postgresql@15-main.service",
		300: "systemd-fsck@dev-sda1.service",
		400: "run-u12.service", // transient: no unit file, not reported
	}
	svcs, truncated, err := CollectSystemdServices(systemdHost(), running)
	if err != nil || truncated {
		t.Fatalf("err=%v truncated=%v", err, truncated)
	}
	got := map[string]Service{}
	var names []string
	for _, s := range svcs {
		got[s.Name] = s
		names = append(names, s.Name)
	}
	wantNames := []string{
		"apt-daily.service", "cron.service", "cups.service", "custom.service", "dyn.service",
		"empty-masked.service", "nginx.service", "postgresql@15-main.service", "snapd.service",
		"ssh.service", "systemd-fsck@dev-sda1.service", "systemd-journald.service",
	}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("names = %v\nwant %v", names, wantNames)
	}

	want := map[string]Service{
		"ssh.service": {Manager: "systemd", Name: "ssh.service", DisplayName: "OpenBSD Secure Shell server",
			StartMode: "auto", State: "running", RunAs: "root", BinaryPath: "/usr/sbin/sshd",
			Attrs: map[string]any{"unit_path": "/lib/systemd/system/ssh.service"}},
		"cron.service": {Manager: "systemd", Name: "cron.service", DisplayName: "Regular background program processing daemon",
			StartMode: "auto", State: "stopped", RunAs: "nobody", BinaryPath: "/usr/sbin/cron",
			Attrs: map[string]any{"unit_path": "/lib/systemd/system/cron.service"}},
		"postgresql@15-main.service": {Manager: "systemd", Name: "postgresql@15-main.service", DisplayName: "PostgreSQL Cluster %i",
			StartMode: "auto", State: "running", RunAs: "postgres", BinaryPath: "/usr/bin/pg_ctlcluster",
			Attrs: map[string]any{"unit_path": "/lib/systemd/system/postgresql@.service"}},
		"systemd-fsck@dev-sda1.service": {Manager: "systemd", Name: "systemd-fsck@dev-sda1.service", DisplayName: "File System Check on %f",
			StartMode: "static", State: "running", RunAs: "root", BinaryPath: "/lib/systemd/systemd-fsck",
			Attrs: map[string]any{"unit_path": "/lib/systemd/system/systemd-fsck@.service"}},
		"systemd-journald.service": {Manager: "systemd", Name: "systemd-journald.service", DisplayName: "Journal Service",
			StartMode: "auto", State: "stopped", RunAs: "root", BinaryPath: "/lib/systemd/systemd-journald",
			Attrs: map[string]any{"unit_path": "/lib/systemd/system/systemd-journald.service"}},
		"cups.service": {Manager: "systemd", Name: "cups.service", DisplayName: "CUPS Scheduler",
			StartMode: "manual", State: "stopped", RunAs: "root", BinaryPath: "/usr/sbin/cupsd",
			Attrs: map[string]any{"unit_path": "/lib/systemd/system/cups.service", "activated_by": "cups.socket"}},
		"apt-daily.service": {Manager: "systemd", Name: "apt-daily.service", DisplayName: "Daily apt download activities",
			StartMode: "manual", State: "stopped", RunAs: "root", BinaryPath: "/usr/lib/apt/apt.systemd.daily",
			Attrs: map[string]any{"unit_path": "/lib/systemd/system/apt-daily.service", "activated_by": "apt-daily.timer"}},
		"snapd.service":        {Manager: "systemd", Name: "snapd.service", StartMode: "masked", State: "stopped"},
		"empty-masked.service": {Manager: "systemd", Name: "empty-masked.service", StartMode: "masked", State: "stopped"},
		// Drop-ins: ExecStart reset and replaced, User added; [Install] in a
		// drop-in doesn't count, the main file's does.
		"nginx.service": {Manager: "systemd", Name: "nginx.service", DisplayName: "A high performance web server",
			StartMode: "disabled", State: "stopped", RunAs: "www-data", BinaryPath: "/opt/nginx/sbin/nginx",
			Attrs: map[string]any{"unit_path": "/lib/systemd/system/nginx.service"}},
		"dyn.service": {Manager: "systemd", Name: "dyn.service", StartMode: "disabled", State: "stopped",
			BinaryPath: "/opt/my app/bin",
			Attrs:      map[string]any{"unit_path": "/lib/systemd/system/dyn.service", "dynamic_user": true}},
		// Linked from outside the unit dirs with an absolute symlink: re-rooted.
		"custom.service": {Manager: "systemd", Name: "custom.service", DisplayName: "Custom",
			StartMode: "static", State: "stopped", RunAs: "root", BinaryPath: "/opt/custom/bin/custom",
			Attrs: map[string]any{"unit_path": "/opt/custom/custom.service"}},
	}
	for name, w := range want {
		if g := got[name]; !reflect.DeepEqual(g, w) {
			t.Errorf("%s:\n got %+v\nwant %+v", name, g, w)
		}
	}
}

func TestCollectSystemdServicesNoProcAndNoSystemd(t *testing.T) {
	svcs, _, err := CollectSystemdServices(systemdHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range svcs {
		if s.State != "" {
			t.Errorf("%s: state %q without procfs, want empty", s.Name, s.State)
		}
	}
	if _, _, err := CollectSystemdServices(fstest.MapFS{"etc/os-release": unit("ID=alpine\n")}, nil); !errors.Is(err, ErrNoSystemd) {
		t.Errorf("no unit dirs: err = %v, want ErrNoSystemd", err)
	}
}

func TestCollectSystemdServicesCap(t *testing.T) {
	fsys := fstest.MapFS{}
	for i := 0; i < MaxServices+3; i++ {
		fsys[fmt.Sprintf("lib/systemd/system/s%05d.service", i)] = unit("[Service]\nExecStart=/bin/true\n")
	}
	svcs, truncated, err := CollectSystemdServices(fsys, nil)
	if err != nil || !truncated || len(svcs) != MaxServices || svcs[0].Name != "s00000.service" {
		t.Errorf("err=%v truncated=%v n=%d", err, truncated, len(svcs))
	}
}

func TestUnitFromCgroup(t *testing.T) {
	for in, want := range map[string]string{
		"0::/system.slice/ssh.service\n":                                           "ssh.service",
		"0::/../../system.slice/ssh.service\n":                                     "ssh.service", // outside the reader's cgroup namespace
		"0::/system.slice/system-getty.slice/getty@tty1.service\n":                 "getty@tty1.service",
		"0::/system.slice/docker-0123abcd.scope\n":                                 "",
		"0::/user.slice/user-1000.slice/user@1000.service/app.slice/foo.service\n": "",
		"0::/init.scope\n": "",
		"12:pids:/system.slice/cron.service\n1:name=systemd:/system.slice/cron.service\n0::/system.slice/cron.service\n": "cron.service",
		"": "",
	} {
		if got := unitFromCgroup(in); got != want {
			t.Errorf("unitFromCgroup(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExecBinary(t *testing.T) {
	for in, want := range map[string]string{
		"/usr/sbin/sshd -D":           "/usr/sbin/sshd",
		"-/usr/bin/foo":               "/usr/bin/foo",
		"@/usr/bin/foo foo-argv0 --x": "/usr/bin/foo",
		"+!/usr/bin/foo":              "/usr/bin/foo",
		`"/opt/my app/bin" --flag`:    "/opt/my app/bin",
		"/bin/true":                   "/bin/true",
		"":                            "",
	} {
		if got := execBinary(in); got != want {
			t.Errorf("execBinary(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProcessUnits(t *testing.T) {
	p := newFakeProc(t)
	p.process("1", "systemd", "0::/init.scope\n", "")
	p.process("812", "sshd", "0::/system.slice/ssh.service\n", "")
	p.process("900", "bash", "0::/user.slice/user-1000.slice/session-3.scope\n", "")
	p.file("self/comm", "agent") // non-numeric entries are ignored
	got := ProcessUnits(p.root)
	if want := map[int]string{812: "ssh.service"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ProcessUnits = %v, want %v", got, want)
	}
}
