package ingest

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/hostfacts"
)

func kinds(sets []hostfacts.Set) map[string]hostfacts.Set {
	out := map[string]hostfacts.Set{}
	for _, s := range sets {
		out[s.Kind] = s
	}
	return out
}

const fullPayload = `{"schema_version": 1, ` + jammy + `,
	"host": {"ref": "local", "os_family": "linux"},
	"collectors": {
		"os": {"status": "ok"},
		"tcp_listeners": {"status": "ok"},
		"udp_listeners": {"status": "ok", "truncated": true},
		"systemd_services": {"status": "ok"},
		"local_users": {"status": "ok"},
		"uptime": {"status": "ok"},
		"arch": {"status": "ok"},
		"deleted_libs": {"status": "ok"},
		"unattended_upgrades": {"status": "error", "error": "boom"}
	},
	"listening_sockets": [
		{"proto": "tcp", "local_addr": "0.0.0.0", "port": 5432, "pid": 7, "process_name": "postgres"},
		{"proto": "tcp6", "local_addr": "0000:0000:0000:0000:0000:0000:0000:0000", "port": 22},
		{"proto": "tcp6", "local_addr": "::ffff:127.0.0.1", "port": 631},
		{"proto": "tcp", "local_addr": "not-an-ip", "port": 80},
		{"proto": "tcp", "local_addr": "127.0.0.1", "port": 0},
		{"proto": "udp", "local_addr": "127.0.0.53", "port": 53, "process_name": "systemd-resolve"}
	],
	"services": [
		{"manager": "systemd", "name": "ssh.service", "start_mode": "auto", "state": "running", "run_as": "root",
		 "binary_path": "/usr/sbin/sshd", "attrs": {"unit_path": "/lib/systemd/system/ssh.service"}},
		{"manager": "launchd", "name": "com.apple.x"},
		{"manager": "systemd", "name": ""}
	],
	"users": [
		{"name": "root", "uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash", "groups": ["root"], "login_shell": true},
		{"name": "alice", "uid": 1000, "gid": 1000, "groups": ["alice", "sudo"], "login_shell": true, "admin": true},
		{"name": "neg", "uid": -1, "gid": 0}
	],
	"uptime_seconds": 3600,
	"facts": {
		"needs_restart": {"processes": [{"pid": 812, "name": "sshd", "libraries": ["/usr/lib/libssl.so.3"]}], "unreadable_processes": 2},
		"unattended_upgrades": {"enabled": true}
	}
}`

func TestPlanFacts(t *testing.T) {
	p := decode(t, strings.Replace(fullPayload, jammy,
		`"os": {"id": "ubuntu", "version_id": "22.04", "codename": "jammy", "arch": "amd64"}`, 1))
	sets, notes := planFacts(p)
	got := kinds(sets)
	if len(got) != 4 {
		t.Fatalf("kinds = %v", got)
	}

	tcp := got["listeners:tcp"]
	var keys []string
	for _, r := range tcp.Rows {
		keys = append(keys, r.Key)
	}
	if want := []string{"tcp 0.0.0.0:5432", "tcp6 [::]:22", "tcp6 [::ffff:127.0.0.1]:631"}; !reflect.DeepEqual(keys, want) {
		t.Errorf("tcp keys = %v, want %v", keys, want)
	}
	if tcp.Additive || tcp.Scope != "tcp" {
		t.Errorf("tcp set: additive=%v scope=%q", tcp.Additive, tcp.Scope)
	}
	if want := []any{"tcp", "tcp", "0.0.0.0", 5432, "postgres"}; !reflect.DeepEqual(tcp.Rows[0].Values, want) {
		t.Errorf("tcp row = %#v", tcp.Rows[0].Values)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "dropped 2") {
		t.Errorf("notes = %v", notes)
	}
	if udp := got["listeners:udp"]; !udp.Additive || len(udp.Rows) != 1 {
		t.Errorf("udp set (truncated): %+v", udp)
	}
	if svc := got["services:systemd"]; len(svc.Rows) != 1 || svc.Rows[0].Key != "systemd/ssh.service" {
		t.Errorf("services = %+v", svc.Rows)
	}
	users := got["users:local"]
	if len(users.Rows) != 2 || users.Rows[0].Key != "alice" {
		t.Fatalf("users = %+v", users.Rows)
	}
	// root is admin by uid even though the payload didn't flag it.
	if root := users.Rows[1].Values; root[7] != true || root[3] != "/root" {
		t.Errorf("root row = %#v", root)
	}

	if up := uptimeSeconds(p); up == nil || *up != 3600 {
		t.Errorf("uptime = %v", up)
	}
	if a := hostArch(p); a != "amd64" {
		t.Errorf("arch = %q", a)
	}
	b, err := linuxFacts(p, "linux")
	if err != nil || strings.Contains(string(b), "unattended") || !strings.Contains(string(b), `"pid":812`) {
		t.Errorf("facts = %s, %v (unattended collector errored: must be dropped)", b, err)
	}
	if b, _ := linuxFacts(p, "windows"); string(b) != "{}" {
		t.Errorf("non-linux facts = %s", b)
	}
}

// A failed or skipped collector never yields a set: its ranges stay open.
// An ok collector with nothing listed yields an empty (closing) set.
func TestPlanFactsAuthority(t *testing.T) {
	p := decode(t, `{"schema_version": 1, `+jammy+`, "collectors": {
		"tcp_listeners": {"status": "error", "error": "x"},
		"udp_listeners": {"status": "ok"},
		"systemd_services": {"status": "skipped", "reason": "no systemd"},
		"uptime": {"status": "error"}, "arch": {"status": "skipped"}},
		"uptime_seconds": 5, "listening_sockets": [{"proto": "tcp", "local_addr": "0.0.0.0", "port": 22}]}`)
	sets, _ := planFacts(p)
	got := kinds(sets)
	if len(got) != 1 {
		t.Fatalf("kinds = %v, want only listeners:udp", got)
	}
	if udp := got["listeners:udp"]; len(udp.Rows) != 0 || udp.Additive {
		t.Errorf("ok-and-empty udp = %+v", udp)
	}
	if uptimeSeconds(p) != nil || hostArch(p) != "" {
		t.Error("uptime/arch trusted without an ok collector")
	}

	// Legacy (pre-collectors) agents: TCP listeners are authoritative, nothing else.
	legacy := decode(t, `{"schema_version": 1, `+jammy+`, "uptime_seconds": 5,
		"listening_sockets": [{"proto": "tcp", "local_addr": "0.0.0.0", "port": 22}]}`)
	sets, _ = planFacts(legacy)
	if got := kinds(sets); len(got) != 1 || len(got["listeners:tcp"].Rows) != 1 {
		t.Errorf("legacy kinds = %v", got)
	}
	if uptimeSeconds(legacy) != nil {
		t.Error("legacy uptime trusted")
	}
}

func TestHostArchValidation(t *testing.T) {
	for arch, want := range map[string]string{"amd64": "amd64", "ppc64el": "ppc64el", "AMD64": "", "x86 64": "", "": ""} {
		p := SnapshotPayload{OS: OSRelease{Arch: arch}, Collectors: map[string]CollectorStatus{"arch": {Status: "ok"}}}
		if got := hostArch(p); got != want {
			t.Errorf("hostArch(%q) = %q, want %q", arch, got, want)
		}
	}
}

func TestBuildSnapshotInputFacts(t *testing.T) {
	p := decode(t, fullPayload)
	in := buildSnapshotInput(p, "agent", time.Now(), time.Now(), "203.0.113.1")
	if len(in.FactSets) != 4 || in.UptimeSeconds == nil || len(in.Facts) < 3 {
		t.Errorf("fact sets=%d uptime=%v facts=%s", len(in.FactSets), in.UptimeSeconds, in.Facts)
	}
	if len(in.ListeningSockets) != 6 {
		t.Errorf("listening_sockets rows = %d, want all 6 (per-snapshot table keeps what was sent)", len(in.ListeningSockets))
	}
}
