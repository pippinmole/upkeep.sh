package store

// Dashboard management functions (mgmt_*, migration 0011): ownership
// scoping, merge correctness, duplicate dismissal, detach, archive.
// Skipped unless SW_TEST_DATABASE_URL is set.

import (
	"context"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/inventory"
)

// mgmt runs one mgmt_* function call and returns its status.
func (f *agentFixture) mgmt(q string, args ...any) string {
	f.t.Helper()
	var st string
	if err := f.s.Pool.QueryRow(context.Background(), q, args...).Scan(&st); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
	return st
}

// otherUser creates a second user (another tenant), removed on cleanup.
func (f *agentFixture) otherUser() string {
	f.t.Helper()
	var id string
	if err := f.s.Pool.QueryRow(context.Background(), `INSERT INTO workspaces (name) VALUES ($1) RETURNING id`,
		f.tag+"-b@test.invalid").Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _, _ = f.s.Pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id = $1`, id) })
	return id
}

// pushInv pushes a deb inventory from agentID at a given time.
func (f *agentFixture) pushInv(agentID string, claim HostClaim, at time.Time, names ...string) SnapshotResult {
	f.t.Helper()
	items := make([]inventory.Item, 0, len(names))
	for _, n := range names {
		items = append(items, inventory.Item{Name: n, Version: "1", Arch: "amd64", Source: n, SourceVersion: "1"})
	}
	res, err := f.s.InsertSnapshot(context.Background(), SnapshotInput{
		AgentID: agentID, Host: claim, Agent: AgentReport{IntervalSeconds: 60},
		SchemaVersion: 1, CollectedAt: at, InventoryAt: at,
		OSFamily: "linux", OSKnown: true, OSID: "ubuntu", OSVersionID: "22.04", OSCodename: "jammy",
		Inventory: []inventory.Set{inventory.NewSet("deb", f.tag, "jammy", items)},
	})
	if err != nil {
		f.t.Fatalf("push: %v", err)
	}
	return res
}

// cleanSoftware removes this fixture's software_versions after its hosts.
func (f *agentFixture) cleanSoftware() {
	f.t.Cleanup(func() {
		ctx := context.Background()
		_, _ = f.s.Pool.Exec(ctx, `DELETE FROM workspaces WHERE id = $1`, f.workspaceID)
		_, _ = f.s.Pool.Exec(ctx, `DELETE FROM software_versions WHERE distro = $1`, f.tag)
	})
}

// Every mutation is scoped by user id: another user's agent or host looks
// exactly like a missing one, and nothing changes.
func TestMgmtCrossTenant(t *testing.T) {
	f := newAgentFixture(t)
	a, b := f.enroll(""), f.enroll("")
	mid := f.machineID()
	h := f.push(a, HostClaim{MachineID: mid, Hostname: "victim"}).HostID
	dup := f.push(b, HostClaim{MachineID: mid, Hostname: "victim"}).HostID // flagged duplicate of h
	if err := f.s.Pool.QueryRow(context.Background(), `UPDATE agents SET revoked_at = now() - interval '1 hour'
		WHERE id = $1 RETURNING id`, b).Scan(new(string)); err != nil {
		t.Fatal(err)
	}
	other := f.otherUser()

	calls := []struct {
		q    string
		args []any
	}{
		{`SELECT mgmt_revoke_agent($1, $2)`, []any{other, a}},
		{`SELECT mgmt_request_rotation($1, $2)`, []any{other, a}},
		{`SELECT mgmt_rename_host($1, $2, 'pwned')`, []any{other, h}},
		{`SELECT mgmt_set_host_archived($1, $2, true)`, []any{other, h}},
		{`SELECT mgmt_delete_host($1, $2, 'victim')`, []any{other, h}},
		{`SELECT mgmt_dismiss_duplicate($1, $2)`, []any{other, dup}},
		{`SELECT mgmt_merge_host($1, $2, $3)`, []any{other, dup, h}},
		{`SELECT mgmt_detach_host($1, $2, $3)`, []any{other, b, dup}},
	}
	for _, c := range calls {
		if st := f.mgmt(c.q, c.args...); st != "not_found" {
			t.Errorf("%s as other user = %q, want not_found", c.q, st)
		}
	}
	if n := f.count(`SELECT count(*) FROM agents WHERE id = $1 AND revoked_at IS NULL`, a); n != 1 {
		t.Error("agent revoked by another user")
	}
	if n := f.count(`SELECT count(*) FROM agent_credentials WHERE agent_id = $1 AND rotate_requested_at IS NULL`, a); n != 1 {
		t.Error("rotation requested by another user")
	}
	if n := f.count(`SELECT count(*) FROM hosts WHERE id = $1 AND label IS NULL AND archived_at IS NULL`, h); n != 1 {
		t.Error("host renamed/archived/deleted by another user")
	}
	if n := f.count(`SELECT count(*) FROM hosts WHERE id = $1 AND duplicate_of = $2 AND merged_into IS NULL`, dup, h); n != 1 {
		t.Error("duplicate dismissed/merged by another user")
	}
	if n := f.count(`SELECT count(*) FROM agent_hosts WHERE agent_id = $1 AND host_id = $2`, b, dup); n != 1 {
		t.Error("host detached by another user")
	}
	// A host id of another tenant can't be named as the merge target either.
	otherHost, err := f.s.CreateHost(context.Background(), other, "theirs")
	if err != nil {
		t.Fatal(err)
	}
	if st := f.mgmt(`SELECT mgmt_merge_host($1, $2, $3)`, f.workspaceID, dup, otherHost); st != "not_found" {
		t.Errorf("merge into another tenant's host = %q", st)
	}
}

func TestMgmtAgentActions(t *testing.T) {
	f := newAgentFixture(t)
	id := f.enroll("")
	if st := f.mgmt(`SELECT mgmt_request_rotation($1, $2)`, f.workspaceID, id); st != "ok" {
		t.Fatalf("request rotation: %s", st)
	}
	if c := f.cred(id); !c.RotateRequested {
		t.Error("rotate_requested_at not set")
	}
	if st := f.mgmt(`SELECT mgmt_revoke_agent($1, $2)`, f.workspaceID, id); st != "ok" {
		t.Fatalf("revoke: %s", st)
	}
	if c := f.cred(id); !c.Revoked || c.RotateRequested {
		t.Errorf("after revoke: %+v", c)
	}
	if st := f.mgmt(`SELECT mgmt_request_rotation($1, $2)`, f.workspaceID, id); st != "revoked" {
		t.Errorf("rotate revoked agent: %s", st)
	}
	// Ingest refuses the revoked agent's pushes before touching anything
	// (handler); the store itself still resolves (auth is the handler's).
}

func TestMgmtRenameArchiveDelete(t *testing.T) {
	f := newAgentFixture(t)
	a := f.enroll("")
	h := f.push(a, HostClaim{MachineID: f.machineID(), Hostname: "web-1"}).HostID

	if st := f.mgmt(`SELECT mgmt_rename_host($1, $2, $3)`, f.workspaceID, h, "  Primary web  "); st != "ok" {
		t.Fatal(st)
	}
	if n := f.count(`SELECT count(*) FROM hosts WHERE id = $1 AND label = 'Primary web' AND hostname = 'web-1'`, h); n != 1 {
		t.Error("label not trimmed/set")
	}
	f.mgmt(`SELECT mgmt_rename_host($1, $2, $3)`, f.workspaceID, h, "   ")
	if n := f.count(`SELECT count(*) FROM hosts WHERE id = $1 AND label IS NULL`, h); n != 1 {
		t.Error("blank label not cleared")
	}

	if st := f.mgmt(`SELECT mgmt_set_host_archived($1, $2, true)`, f.workspaceID, h); st != "ok" {
		t.Fatal(st)
	}
	// An agent that still collects an archived host keeps recording it,
	// without unarchiving it.
	f.push(a, HostClaim{Hostname: "web-1"})
	if n := f.count(`SELECT count(*) FROM hosts WHERE id = $1 AND archived_at IS NOT NULL`, h); n != 1 {
		t.Error("sticky push unarchived the host")
	}
	f.mgmt(`SELECT mgmt_set_host_archived($1, $2, false)`, f.workspaceID, h)
	if n := f.count(`SELECT count(*) FROM hosts WHERE id = $1 AND archived_at IS NULL`, h); n != 1 {
		t.Error("not unarchived")
	}

	if st := f.mgmt(`SELECT mgmt_delete_host($1, $2, $3)`, f.workspaceID, h, "web-2"); st != "confirmation_mismatch" {
		t.Errorf("delete with wrong confirmation: %s", st)
	}
	if st := f.mgmt(`SELECT mgmt_delete_host($1, $2, $3)`, f.workspaceID, h, "web-1"); st != "ok" {
		t.Fatalf("delete: %s", st)
	}
	for _, q := range []string{
		`SELECT count(*) FROM hosts WHERE id = $1`,
		`SELECT count(*) FROM snapshots WHERE host_id = $1`,
		`SELECT count(*) FROM agent_hosts WHERE host_id = $1`,
		`SELECT count(*) FROM host_identities WHERE host_id = $1`,
	} {
		if n := f.count(q, h); n != 0 {
			t.Errorf("%s = %d after delete", q, n)
		}
	}
	if n := f.count(`SELECT count(*) FROM agents WHERE id = $1`, a); n != 1 {
		t.Error("deleting a host deleted its agent")
	}
}

// A re-attach by identity (new agent on an archived host's machine)
// brings the host back.
func TestReattachUnarchives(t *testing.T) {
	f := newAgentFixture(t)
	old := f.enroll("")
	mid := f.machineID()
	h := f.push(old, HostClaim{MachineID: mid}).HostID
	f.mgmt(`SELECT mgmt_set_host_archived($1, $2, true)`, f.workspaceID, h)
	f.mgmt(`SELECT mgmt_revoke_agent($1, $2)`, f.workspaceID, old)

	res := f.push(f.enroll(""), HostClaim{MachineID: mid})
	if !res.Host.Reattached || res.HostID != h {
		t.Fatalf("reattach: %+v", res.Host)
	}
	if n := f.count(`SELECT count(*) FROM hosts WHERE id = $1 AND archived_at IS NULL`, h); n != 1 {
		t.Error("re-attached host still archived")
	}
}

// "Not a duplicate" clears the flag, and later pushes don't raise it again
// against the same host.
func TestDismissDuplicateSticks(t *testing.T) {
	f := newAgentFixture(t)
	a, b := f.enroll(""), f.enroll("")
	mid := f.machineID()
	ha := f.push(a, HostClaim{MachineID: mid}).HostID
	hb := f.push(b, HostClaim{MachineID: mid}).HostID

	if st := f.mgmt(`SELECT mgmt_dismiss_duplicate($1, $2)`, f.workspaceID, ha); st != "not_flagged" {
		t.Errorf("dismiss unflagged host: %s", st)
	}
	if st := f.mgmt(`SELECT mgmt_dismiss_duplicate($1, $2)`, f.workspaceID, hb); st != "ok" {
		t.Fatalf("dismiss: %s", st)
	}
	for range 2 {
		if res := f.push(b, HostClaim{MachineID: mid}); res.HostID != hb || res.Host.DuplicateOf != "" {
			t.Errorf("push after dismiss: %+v", res)
		}
	}
	if n := f.count(`SELECT count(*) FROM hosts WHERE id = $1 AND duplicate_of IS NULL AND duplicate_dismissed_of = $2`, hb, ha); n != 1 {
		t.Error("flag came back")
	}
	if st := f.mgmt(`SELECT mgmt_merge_host($1, $2, $3)`, f.workspaceID, hb, ha); st != "not_flagged" {
		t.Errorf("merge after dismiss: %s", st)
	}
}

// Merge: the duplicate's agent moves to the original and continues its
// inventory ranges; the duplicate keeps its own history, archived.
func TestMergeDuplicateIntoOriginal(t *testing.T) {
	f := newAgentFixture(t)
	f.cleanSoftware()
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	oldAgent := f.enroll("")
	mid := f.machineID()
	orig := f.pushInv(oldAgent, HostClaim{MachineID: mid, Hostname: "box"}, t0, "a", "b").HostID

	// Reinstall faster than the old agent went inactive: flagged duplicate.
	newAgent := f.enroll("")
	res := f.pushInv(newAgent, HostClaim{MachineID: mid, Hostname: "box"}, t0.Add(time.Minute), "a", "b")
	dup := res.HostID
	if res.Host.DuplicateOf != orig {
		t.Fatalf("not flagged: %+v", res.Host)
	}
	// An extra identity recorded on the duplicate moves with it.
	if _, err := f.s.Pool.Exec(ctx, `INSERT INTO host_identities (workspace_id, kind, value, host_id) VALUES ($1, 'smbios_uuid', $2, $3)`,
		f.workspaceID, f.tag, dup); err != nil {
		t.Fatal(err)
	}

	if st := f.mgmt(`SELECT mgmt_merge_host($1, $2, $3)`, f.workspaceID, orig, dup); st != "not_flagged" {
		t.Errorf("merge the wrong way round: %s", st)
	}
	if st := f.mgmt(`SELECT mgmt_merge_host($1, $2, $3)`, f.workspaceID, dup, orig); st != "ok" {
		t.Fatalf("merge: %s", st)
	}

	if got := f.localHost(newAgent); got != orig {
		t.Errorf("new agent's local host = %s, want the original", got)
	}
	if n := f.count(`SELECT count(*) FROM agent_hosts WHERE host_id = $1`, dup); n != 0 {
		t.Errorf("duplicate still has %d assignments", n)
	}
	if n := f.count(`SELECT count(*) FROM hosts WHERE id = $1 AND archived_at IS NOT NULL AND merged_into = $2 AND duplicate_of IS NULL`, dup, orig); n != 1 {
		t.Error("duplicate not archived/merged")
	}
	if n := f.count(`SELECT count(*) FROM host_identities WHERE host_id = $1`, orig); n != 2 {
		t.Errorf("original has %d identities, want 2", n)
	}
	// History stays where it was recorded.
	if n := f.count(`SELECT count(*) FROM snapshots WHERE host_id = $1`, dup); n != 1 {
		t.Errorf("duplicate snapshots = %d, want 1", n)
	}
	if n := f.count(`SELECT count(*) FROM host_software WHERE host_id = $1 AND removed_at IS NULL`, dup); n != 2 {
		t.Errorf("duplicate open ranges = %d, want 2 (frozen, untouched)", n)
	}

	// The next push from the moved agent lands on the original and
	// continues its ranges: a unchanged (one range since t0), b removed,
	// c added.
	t2 := t0.Add(2 * time.Minute)
	if got := f.pushInv(newAgent, HostClaim{MachineID: mid, Hostname: "box"}, t2, "a", "c").HostID; got != orig {
		t.Fatalf("push after merge went to %s", got)
	}
	type rng struct {
		name    string
		first   time.Time
		removed *time.Time
	}
	rows, err := f.s.Pool.Query(ctx, `
		SELECT sv.name, hs.first_seen_at, hs.removed_at FROM host_software hs
		JOIN software_versions sv ON sv.id = hs.software_id
		WHERE hs.host_id = $1 ORDER BY sv.name, hs.first_seen_at`, orig)
	if err != nil {
		t.Fatal(err)
	}
	var got []rng
	for rows.Next() {
		var r rng
		if err := rows.Scan(&r.name, &r.first, &r.removed); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
	}
	if len(got) != 3 ||
		got[0].name != "a" || !got[0].first.Equal(t0) || got[0].removed != nil ||
		got[1].name != "b" || !got[1].first.Equal(t0) || got[1].removed == nil || !got[1].removed.Equal(t2) ||
		got[2].name != "c" || !got[2].first.Equal(t2) || got[2].removed != nil {
		t.Errorf("original's ranges after merge + push: %+v", got)
	}
	if n := f.count(`SELECT count(*) FROM snapshots WHERE host_id = $1`, orig); n != 2 {
		t.Errorf("original snapshots = %d, want 2", n)
	}

	// Merged hosts stay archived; a second merge is refused.
	if st := f.mgmt(`SELECT mgmt_set_host_archived($1, $2, false)`, f.workspaceID, dup); st != "merged" {
		t.Errorf("unarchive merged host: %s", st)
	}

	// The old agent still has the original as its local host too. It can't
	// be detached while active; once silent (or revoked) it can.
	if st := f.mgmt(`SELECT mgmt_detach_host($1, $2, $3)`, f.workspaceID, oldAgent, orig); st != "agent_active" {
		t.Errorf("detach active agent: %s", st)
	}
	if _, err := f.s.Pool.Exec(ctx, `UPDATE agents SET last_seen_at = now() - interval '1 hour' WHERE id = $1`, oldAgent); err != nil {
		t.Fatal(err)
	}
	if st := f.mgmt(`SELECT mgmt_detach_host($1, $2, $3)`, f.workspaceID, oldAgent, orig); st != "ok" {
		t.Errorf("detach inactive agent: %s", st)
	}
	if n := f.count(`SELECT count(*) FROM agent_hosts WHERE host_id = $1`, orig); n != 1 {
		t.Errorf("original assignments = %d, want 1 (the new agent)", n)
	}
	if st := f.mgmt(`SELECT mgmt_detach_host($1, $2, $3)`, f.workspaceID, oldAgent, orig); st != "not_found" {
		t.Errorf("detach twice: %s", st)
	}
}

// mgmt_agent_active must agree with activeAgentSQL.
func TestMgmtAgentActiveMatchesGo(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	id := f.enroll("")
	cases := []string{
		`UPDATE agents SET last_seen_at = NULL WHERE id = $1`,
		`UPDATE agents SET last_seen_at = now() WHERE id = $1`,
		`UPDATE agents SET last_seen_at = now() - interval '44 minutes', push_interval_seconds = NULL WHERE id = $1`,
		`UPDATE agents SET last_seen_at = now() - interval '46 minutes', push_interval_seconds = NULL WHERE id = $1`,
		`UPDATE agents SET last_seen_at = now() - interval '100 seconds', push_interval_seconds = 10 WHERE id = $1`,
		`UPDATE agents SET last_seen_at = now() - interval '130 seconds', push_interval_seconds = 10 WHERE id = $1`,
		`UPDATE agents SET last_seen_at = now(), revoked_at = now() WHERE id = $1`,
	}
	for _, c := range cases {
		if _, err := f.s.Pool.Exec(ctx, c, id); err != nil {
			t.Fatal(err)
		}
		var goRule, sqlRule bool
		if err := f.s.Pool.QueryRow(ctx, `SELECT `+activeAgentSQL+`, mgmt_agent_active(a.revoked_at, a.last_seen_at, a.push_interval_seconds)
			FROM agents a WHERE a.id = $1`, id).Scan(&goRule, &sqlRule); err != nil {
			t.Fatal(err)
		}
		if goRule != sqlRule {
			t.Errorf("%s: Go %v, SQL %v", c, goRule, sqlRule)
		}
	}
}
