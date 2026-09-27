package store

import (
	"context"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/hostfacts"
)

func svcSet(additive bool, svcs ...[2]string) hostfacts.Set {
	var rows []hostfacts.Row
	for _, s := range svcs {
		rows = append(rows, hostfacts.Row{Key: "systemd/" + s[0], Values: []any{
			"systemd", s[0], nil, "auto", s[1], "root", "/usr/sbin/" + s[0], map[string]any{"unit_path": "/lib/" + s[0]}}})
	}
	return hostfacts.NewSet("services:systemd", hostfacts.ServicesTable, "systemd", rows, additive)
}

func listenerSet(transport string, ports ...int) hostfacts.Set {
	var rows []hostfacts.Row
	for _, p := range ports {
		rows = append(rows, hostfacts.Row{Key: transport + " 0.0.0.0:" + strconv.Itoa(p),
			Values: []any{transport, transport, "0.0.0.0", p, "proc"}})
	}
	return hostfacts.NewSet("listeners:"+transport, hostfacts.ListenersTable, transport, rows, false)
}

func (f *fixture) pushFacts(minute int, sets ...hostfacts.Set) SnapshotResult {
	f.t.Helper()
	at := f.t0.Add(time.Duration(minute) * time.Minute)
	res, err := f.s.InsertSnapshot(context.Background(), SnapshotInput{
		HostID: f.hostID, SchemaVersion: 1, CollectedAt: at, InventoryAt: at,
		OSID: f.distro, OSCodename: "jammy", FactSets: sets,
	})
	if err != nil {
		f.t.Fatalf("push at +%dm: %v", minute, err)
	}
	return res
}

type factRange struct {
	Key, Attr      string
	First, Removed int // minutes after t0; -1 = open
}

// factRanges lists table's ranges for the host as (row_key, attrCol, first, removed).
func (f *fixture) factRanges(table, attrCol string) []factRange {
	f.t.Helper()
	rows, err := f.s.Pool.Query(context.Background(),
		`SELECT row_key, coalesce(`+attrCol+`::text, ''), first_seen_at, removed_at FROM `+table+`
		 WHERE host_id = $1 ORDER BY row_key, first_seen_at`, f.hostID)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []factRange
	for rows.Next() {
		var r factRange
		var first time.Time
		var removed *time.Time
		if err := rows.Scan(&r.Key, &r.Attr, &first, &removed); err != nil {
			f.t.Fatal(err)
		}
		r.First, r.Removed = int(first.Sub(f.t0).Minutes()), -1
		if removed != nil {
			r.Removed = int(removed.Sub(f.t0).Minutes())
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	return out
}

func (f *fixture) wantFactRanges(table, attrCol string, want ...factRange) {
	f.t.Helper()
	if got := f.factRanges(table, attrCol); !reflect.DeepEqual(got, want) {
		f.t.Errorf("%s ranges:\n got %+v\nwant %+v", table, got, want)
	}
}

func factOutcome(res SnapshotResult, kind string) InventoryOutcome {
	for _, r := range res.Facts {
		if r.Kind == kind {
			return r.Outcome
		}
	}
	return ""
}

func TestFactRangesServices(t *testing.T) {
	f := newFixture(t)
	const k = "services:systemd"

	res := f.pushFacts(0, svcSet(false, [2]string{"a", "running"}, [2]string{"b", "running"}, [2]string{"c", "running"}))
	if factOutcome(res, k) != InventoryDiffed || res.Facts[0].Opened != 3 {
		t.Fatalf("first push: %+v", res.Facts)
	}

	// b stops (close + reopen at the same boundary), c goes away, d appears.
	res = f.pushFacts(10, svcSet(false, [2]string{"a", "running"}, [2]string{"b", "stopped"}, [2]string{"d", "running"}))
	if r := res.Facts[0]; r.Opened != 2 || r.Closed != 2 {
		t.Errorf("second push: %+v", r)
	}
	want := []factRange{
		{"systemd/a", "running", 0, -1},
		{"systemd/b", "running", 0, 10},
		{"systemd/b", "stopped", 10, -1},
		{"systemd/c", "running", 0, 10},
		{"systemd/d", "running", 10, -1},
	}
	f.wantFactRanges("host_services", "state", want...)

	// Same set again: short-circuited on the set hash.
	res = f.pushFacts(20, svcSet(false, [2]string{"d", "running"}, [2]string{"b", "stopped"}, [2]string{"a", "running"}))
	if factOutcome(res, k) != InventoryUnchanged {
		t.Errorf("identical push: %+v", res.Facts)
	}

	// Collector not ok this push (no set): nothing closes.
	f.pushFacts(30)
	f.wantFactRanges("host_services", "state", want...)

	// Truncated (additive): a is missing but stays open; d changes.
	res = f.pushFacts(40, svcSet(true, [2]string{"b", "stopped"}, [2]string{"d", "stopped"}))
	if r := res.Facts[0]; r.Outcome != InventoryDiffed || r.Opened != 1 || r.Closed != 1 {
		t.Errorf("additive push: %+v", r)
	}
	var hash *string
	if err := f.s.Pool.QueryRow(context.Background(),
		`SELECT set_hash FROM host_fact_state WHERE host_id = $1 AND kind = $2`, f.hostID, k).Scan(&hash); err != nil || hash != nil {
		t.Errorf("after additive push set_hash = %v, %v; want NULL", hash, err)
	}

	// Stale (collected before the last applied push): stored, not diffed.
	res = f.pushFacts(35, svcSet(false))
	if factOutcome(res, k) != InventoryStale {
		t.Errorf("stale push: %+v", res.Facts)
	}

	// Full push again: the same set as the open ranges, but the hash was
	// NULL so it diffs (finding nothing to change) and restores the hash.
	res = f.pushFacts(50, svcSet(false, [2]string{"a", "running"}, [2]string{"b", "stopped"}, [2]string{"d", "stopped"}))
	if r := res.Facts[0]; r.Outcome != InventoryDiffed || r.Opened+r.Closed != 0 {
		t.Errorf("full push after additive: %+v", r)
	}
	res = f.pushFacts(60, svcSet(false, [2]string{"a", "running"}, [2]string{"b", "stopped"}, [2]string{"d", "stopped"}))
	if factOutcome(res, k) != InventoryUnchanged {
		t.Errorf("hash not restored: %+v", res.Facts)
	}

	// Empty ok set closes everything.
	f.pushFacts(70, svcSet(false))
	for _, r := range f.factRanges("host_services", "state") {
		if r.Removed == -1 {
			t.Errorf("still open after empty set: %+v", r)
		}
	}

	var attrs string
	if err := f.s.Pool.QueryRow(context.Background(),
		`SELECT attrs::text FROM host_services WHERE host_id = $1 AND row_key = 'systemd/a' LIMIT 1`, f.hostID).Scan(&attrs); err != nil || attrs != `{"unit_path": "/lib/a"}` {
		t.Errorf("attrs = %s, %v", attrs, err)
	}
}

// TCP and UDP are separate kinds in one table: diffing one never touches
// the other's rows.
func TestFactRangesListenerScopes(t *testing.T) {
	f := newFixture(t)
	f.pushFacts(0, listenerSet("tcp", 22, 5432), listenerSet("udp", 53))
	f.pushFacts(10, listenerSet("tcp", 22)) // udp collector failed this push
	f.pushFacts(20, listenerSet("udp"))     // tcp failed; udp ok and empty
	f.wantFactRanges("host_listeners", "port",
		factRange{"tcp 0.0.0.0:22", "22", 0, -1},
		factRange{"tcp 0.0.0.0:5432", "5432", 0, 10},
		factRange{"udp 0.0.0.0:53", "53", 0, 20},
	)
}

func TestFactRangesUsersAndSnapshotColumns(t *testing.T) {
	f := newFixture(t)
	users := hostfacts.NewSet("users:local", hostfacts.UsersTable, "", []hostfacts.Row{
		{Key: "alice", Values: []any{"alice", int64(1000), int64(1000), "/home/alice", "/bin/bash", []string{"alice", "sudo"}, true, true}},
		{Key: "svc", Values: []any{"svc", int64(998), int64(998), nil, nil, []string{}, false, false}},
	}, false)
	up := int64(3600)
	at := f.t0.Add(time.Minute)
	ctx := context.Background()
	if _, err := f.s.InsertSnapshot(ctx, SnapshotInput{
		HostID: f.hostID, SchemaVersion: 1, CollectedAt: at, InventoryAt: at, OSID: f.distro,
		FactSets: []hostfacts.Set{users}, UptimeSeconds: &up, Arch: "arm64",
		Facts: []byte(`{"needs_restart":{"processes":[],"unreadable_processes":0}}`),
	}); err != nil {
		t.Fatal(err)
	}
	// An older push arriving late must not roll hosts.arch back; an unknown
	// arch on a newer push keeps it.
	early := f.t0
	if _, err := f.s.InsertSnapshot(ctx, SnapshotInput{
		HostID: f.hostID, SchemaVersion: 1, CollectedAt: early, InventoryAt: early, OSID: f.distro, Arch: "amd64",
	}); err != nil {
		t.Fatal(err)
	}
	later := f.t0.Add(2 * time.Minute)
	if _, err := f.s.InsertSnapshot(ctx, SnapshotInput{
		HostID: f.hostID, SchemaVersion: 1, CollectedAt: later, InventoryAt: later, OSID: f.distro,
	}); err != nil {
		t.Fatal(err)
	}

	var hostArch *string
	if err := f.s.Pool.QueryRow(ctx, `SELECT arch FROM hosts WHERE id = $1`, f.hostID).Scan(&hostArch); err != nil || hostArch == nil || *hostArch != "arm64" {
		t.Errorf("hosts.arch = %v, %v", hostArch, err)
	}
	var (
		uptime *int64
		arch   *string
		facts  string
	)
	if err := f.s.Pool.QueryRow(ctx, `SELECT uptime_seconds, arch, facts::text FROM snapshots
		WHERE host_id = $1 AND collected_at = $2`, f.hostID, at).Scan(&uptime, &arch, &facts); err != nil {
		t.Fatal(err)
	}
	if uptime == nil || *uptime != 3600 || arch == nil || *arch != "arm64" || facts != `{"needs_restart": {"processes": [], "unreadable_processes": 0}}` {
		t.Errorf("snapshot columns: uptime=%v arch=%v facts=%s", uptime, arch, facts)
	}
	if err := f.s.Pool.QueryRow(ctx, `SELECT facts::text FROM snapshots WHERE host_id = $1 AND collected_at = $2`,
		f.hostID, later).Scan(&facts); err != nil || facts != "{}" {
		t.Errorf("facts without input = %s, %v", facts, err)
	}

	var groups []string
	var admin bool
	if err := f.s.Pool.QueryRow(ctx, `SELECT groups, admin FROM host_users WHERE host_id = $1 AND name = 'alice' AND removed_at IS NULL`,
		f.hostID).Scan(&groups, &admin); err != nil || !reflect.DeepEqual(groups, []string{"alice", "sudo"}) || !admin {
		t.Errorf("alice: groups=%v admin=%v err=%v", groups, admin, err)
	}
}
