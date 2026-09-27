package hostfacts

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func svcRow(name, state string) Row {
	return Row{Key: "systemd/" + name, Values: []any{"systemd", name, nil, "auto", state, "root", "/usr/sbin/x", map[string]any{"unit_path": "/lib/" + name}}}
}

func TestNewSetCanonical(t *testing.T) {
	a := NewSet("services:systemd", ServicesTable, "systemd",
		[]Row{svcRow("b.service", "running"), svcRow("a.service", "stopped"), svcRow("b.service", "stopped")}, false)
	b := NewSet("services:systemd", ServicesTable, "systemd",
		[]Row{svcRow("a.service", "stopped"), svcRow("b.service", "running")}, false)
	if a.Hash != b.Hash {
		t.Error("order / duplicates changed the set hash")
	}
	if len(a.Rows) != 2 || a.Rows[0].Key != "systemd/a.service" || a.Rows[1].Values[4] != "running" {
		t.Errorf("rows not sorted/deduped keeping first: %+v", a.Rows)
	}
	c := NewSet("services:systemd", ServicesTable, "systemd",
		[]Row{svcRow("a.service", "running"), svcRow("b.service", "running")}, false)
	if c.Hash == b.Hash || c.Rows[0].Hash == b.Rows[0].Hash {
		t.Error("an attribute change must change the row and set hash")
	}
	if c.Rows[1].Hash != b.Rows[1].Hash {
		t.Error("an unchanged row must keep its hash")
	}
	// nil vs "" are different values.
	d := NewSet("users:local", UsersTable, "", []Row{{Key: "x", Values: []any{nil}}}, false)
	e := NewSet("users:local", UsersTable, "", []Row{{Key: "x", Values: []any{""}}}, false)
	if d.Rows[0].Hash == e.Rows[0].Hash {
		t.Error("nil and empty string hash equal")
	}
	if empty := NewSet("users:local", UsersTable, "", nil, false); empty.Rows == nil || empty.Hash == "" {
		t.Error("empty set should have [] rows and a hash")
	}
}

func TestDiff(t *testing.T) {
	cur := NewSet("services:systemd", ServicesTable, "systemd",
		[]Row{svcRow("a.service", "running"), svcRow("b.service", "running"), svcRow("c.service", "running")}, false)
	open := map[string]string{}
	for _, r := range cur.Rows {
		open[r.Key] = r.Hash
	}

	next := NewSet("services:systemd", ServicesTable, "systemd",
		[]Row{svcRow("a.service", "running"), svcRow("b.service", "stopped"), svcRow("d.service", "running")}, false)
	add, closeKeys := Diff(open, next)
	if got := keys(add); !reflect.DeepEqual(got, []string{"systemd/b.service", "systemd/d.service"}) {
		t.Errorf("add = %v", got)
	}
	if !reflect.DeepEqual(closeKeys, []string{"systemd/b.service", "systemd/c.service"}) {
		t.Errorf("close = %v", closeKeys)
	}

	// Additive (truncated): c is missing but not closed; b still replaced.
	next.Additive = true
	add, closeKeys = Diff(open, next)
	if len(add) != 2 || !reflect.DeepEqual(closeKeys, []string{"systemd/b.service"}) {
		t.Errorf("additive: add=%v close=%v", keys(add), closeKeys)
	}

	// Identical set: nothing.
	add, closeKeys = Diff(open, cur)
	if add != nil || closeKeys != nil {
		t.Errorf("identical: add=%v close=%v", keys(add), closeKeys)
	}
}

func keys(rows []Row) []string {
	var out []string
	for _, r := range rows {
		out = append(out, r.Key)
	}
	return out
}

func TestValidateLinuxFacts(t *testing.T) {
	raw := json.RawMessage(`{
		"needs_restart": {"processes": [
			{"pid": 812, "name": "sshd", "unit": "ssh.service", "libraries": ["/usr/lib/libssl.so.3"]},
			{"pid": 0, "name": "bogus", "libraries": []}
		], "unreadable_processes": -3, "future_field": 1},
		"unattended_upgrades": {"enabled": true, "unattended_upgrade": "1",
			"last_apt_update": "2026-09-26T06:12:00+02:00", "last_apt_update_source": "update-success-stamp",
			"last_unattended_run": "yesterday"},
		"something_new": {"x": 1}
	}`)
	b, f, err := ValidateLinuxFacts(raw, true, true)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"needs_restart":{"processes":[{"pid":812,"name":"sshd","unit":"ssh.service","libraries":["/usr/lib/libssl.so.3"]}],"unreadable_processes":0},` +
		`"unattended_upgrades":{"unattended_upgrade":"1","enabled":true,"last_apt_update":"2026-09-26T04:12:00Z","last_apt_update_source":"update-success-stamp"}}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
	if f.NeedsRestart == nil || len(f.NeedsRestart.Processes) != 1 {
		t.Errorf("decoded: %+v", f)
	}

	// Members whose collector isn't ok are dropped.
	b, _, _ = ValidateLinuxFacts(raw, false, true)
	if strings.Contains(string(b), "needs_restart") {
		t.Errorf("needs_restart kept without an ok collector: %s", b)
	}
	b, _, _ = ValidateLinuxFacts(raw, false, false)
	if string(b) != "{}" {
		t.Errorf("nothing ok: %s", b)
	}
	if b, _, err := ValidateLinuxFacts(json.RawMessage(`{"needs_restart": 5}`), true, true); err == nil || string(b) != "{}" {
		t.Errorf("malformed: %s, %v", b, err)
	}
	if b, _, err := ValidateLinuxFacts(nil, true, true); err != nil || string(b) != "{}" {
		t.Errorf("absent: %s, %v", b, err)
	}
}

func TestClip(t *testing.T) {
	for _, tc := range []struct {
		in   string
		n    int
		want string
	}{
		{"  abc  ", 10, "abc"},
		{"a\x00b", 10, "ab"},
		{"abcdef", 3, "abc"},
		{"héllo", 2, "h"}, // é is two bytes; don't split it
		{"bad\xffutf8", 20, "badutf8"},
	} {
		if got := Clip(tc.in, tc.n); got != tc.want {
			t.Errorf("Clip(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}
