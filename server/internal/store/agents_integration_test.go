package store

// Agent/host split integration tests (migration 0008, resolveHost). Skipped
// unless SW_TEST_DATABASE_URL is set; see inventory_integration_test.go.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type agentFixture struct {
	t      *testing.T
	s      *Store
	userID string
	tag    string
	n      int
}

func newAgentFixture(t *testing.T) *agentFixture {
	t.Helper()
	dsn := os.Getenv("SW_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SW_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	f := &agentFixture{t: t, s: s, tag: "swtest-" + hex.EncodeToString(b)}
	if err := s.Pool.QueryRow(ctx, `INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id`,
		f.tag+"@test.invalid").Scan(&f.userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.Pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, f.userID) // cascades agents, hosts, ...
		s.Close()
	})
	return f
}

// enroll issues a token (optionally pre-named) and enrolls an agent with it.
func (f *agentFixture) enroll(tokenName string) string {
	f.t.Helper()
	ctx := context.Background()
	f.n++
	token := f.tag + "-tok-" + string(rune('a'+f.n))
	var name any
	if tokenName != "" {
		name = tokenName
	}
	if _, err := f.s.Pool.Exec(ctx, `INSERT INTO enrollment_tokens (token, user_id, expires_at, agent_name)
		VALUES ($1, $2, now() + interval '1 hour', $3)`, token, f.userID, name); err != nil {
		f.t.Fatal(err)
	}
	id, err := f.s.EnrollAgent(ctx, EnrollInput{Token: token, Hostname: "container-" + f.tag,
		Version: "0.9.0", Platform: "linux/amd64", SecretHash: "hash"})
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

// push stores a minimal snapshot from agentID with the given claim.
func (f *agentFixture) push(agentID string, claim HostClaim) SnapshotResult {
	f.t.Helper()
	res, err := f.tryPush(agentID, claim)
	if err != nil {
		f.t.Fatalf("push: %v", err)
	}
	return res
}

func (f *agentFixture) tryPush(agentID string, claim HostClaim) (SnapshotResult, error) {
	now := time.Now().UTC()
	return f.s.InsertSnapshot(context.Background(), SnapshotInput{
		AgentID: agentID, Host: claim, Agent: AgentReport{Version: "1.0.0", Platform: "linux/arm64", IntervalSeconds: 60},
		SchemaVersion: 1, CollectedAt: now, InventoryAt: now,
		OSFamily: "linux", OSKnown: true, OSID: "ubuntu", OSVersionID: "22.04", OSCodename: "jammy",
		KernelRelease: "6.8.0-45-generic",
	})
}

func (f *agentFixture) count(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.s.Pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *agentFixture) hostsOfUser() int {
	return f.count(`SELECT count(*) FROM hosts WHERE user_id = $1`, f.userID)
}

func (f *agentFixture) localHost(agentID string) string {
	f.t.Helper()
	var h string
	if err := f.s.Pool.QueryRow(context.Background(),
		`SELECT host_id FROM agent_hosts WHERE agent_id = $1 AND mode = 'local'`, agentID).Scan(&h); err != nil {
		f.t.Fatal(err)
	}
	return h
}

func (f *agentFixture) machineID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func TestEnrollCreatesAgentNotHost(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	id := f.enroll("")

	var name, version, platform string
	var lastSeen *time.Time
	if err := f.s.Pool.QueryRow(ctx, `SELECT name, agent_version, platform, last_seen_at FROM agents WHERE id = $1 AND user_id = $2`,
		id, f.userID).Scan(&name, &version, &platform, &lastSeen); err != nil {
		t.Fatal(err)
	}
	if name != "container-"+f.tag || version != "0.9.0" || platform != "linux/amd64" || lastSeen != nil {
		t.Errorf("agent = %q %q %q %v", name, version, platform, lastSeen)
	}
	if n := f.hostsOfUser(); n != 0 {
		t.Errorf("enrollment created %d hosts, want 0", n)
	}
	cred, err := f.s.AgentCredential(ctx, id)
	if err != nil || cred.SecretHash != "hash" || cred.UserID != f.userID || cred.Revoked {
		t.Errorf("credential = %+v, %v", cred, err)
	}
	if n := f.count(`SELECT count(*) FROM enrollment_tokens WHERE user_id = $1`, f.userID); n != 0 {
		t.Errorf("token not consumed")
	}
	// Replaying the consumed token fails.
	if _, err := f.s.EnrollAgent(ctx, EnrollInput{Token: f.tag + "-tok-b", SecretHash: "h"}); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("replayed token: err = %v, want ErrNoRows", err)
	}
	// A token's agent_name wins over the enrolling hostname.
	named := f.enroll("db-box")
	if err := f.s.Pool.QueryRow(ctx, `SELECT name FROM agents WHERE id = $1`, named).Scan(&name); err != nil || name != "db-box" {
		t.Errorf("named agent = %q, %v", name, err)
	}
}

func TestFirstPushCreatesHostAndAssignment(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	a := f.enroll("")
	mid := f.machineID()

	res := f.push(a, HostClaim{Ref: "local", MachineID: mid, Hostname: "web-1"})
	if !res.Host.Created || res.Host.Reattached || res.Host.DuplicateOf != "" || res.HostID == "" {
		t.Fatalf("first push: %+v", res.Host)
	}
	if got := f.localHost(a); got != res.HostID {
		t.Errorf("local assignment -> %s, want %s", got, res.HostID)
	}
	var hostname, fam, osID, osVer, codename, kernel string
	if err := f.s.Pool.QueryRow(ctx, `SELECT hostname, os_family, os_id, os_version, os_codename, kernel FROM hosts WHERE id = $1`,
		res.HostID).Scan(&hostname, &fam, &osID, &osVer, &codename, &kernel); err != nil {
		t.Fatal(err)
	}
	if hostname != "web-1" || fam != "linux" || osID != "ubuntu" || osVer != "22.04" || codename != "jammy" || kernel != "6.8.0-45-generic" {
		t.Errorf("host summary = %s %s %s %s %s %s", hostname, fam, osID, osVer, codename, kernel)
	}
	if n := f.count(`SELECT count(*) FROM host_identities WHERE user_id = $1 AND kind = 'machine_id' AND value = $2 AND host_id = $3`,
		f.userID, mid, res.HostID); n != 1 {
		t.Errorf("identity rows = %d", n)
	}
	if n := f.count(`SELECT count(*) FROM snapshots WHERE id = $1 AND agent_id = $2 AND host_id = $3`, res.SnapshotID, a, res.HostID); n != 1 {
		t.Errorf("snapshot agent_id/host_id not recorded")
	}
	var version, platform string
	var interval int
	if err := f.s.Pool.QueryRow(ctx, `SELECT agent_version, platform, push_interval_seconds FROM agents
		WHERE id = $1 AND last_seen_at IS NOT NULL`, a).Scan(&version, &platform, &interval); err != nil {
		t.Fatal(err)
	}
	if version != "1.0.0" || platform != "linux/arm64" || interval != 60 {
		t.Errorf("agent report = %s %s %d", version, platform, interval)
	}
	if n := f.count(`SELECT count(*) FROM agent_hosts WHERE agent_id = $1 AND last_collected_at IS NOT NULL`, a); n != 1 {
		t.Errorf("last_collected_at not set")
	}

	// Later pushes land on the same host and refresh the hostname.
	res2 := f.push(a, HostClaim{Ref: "local", MachineID: mid, Hostname: "web-1-renamed"})
	if res2.HostID != res.HostID || res2.Host.Created {
		t.Errorf("second push: %+v", res2.Host)
	}
	if err := f.s.Pool.QueryRow(ctx, `SELECT hostname FROM hosts WHERE id = $1`, res.HostID).Scan(&hostname); err != nil || hostname != "web-1-renamed" {
		t.Errorf("hostname = %q, %v", hostname, err)
	}
	if n := f.hostsOfUser(); n != 1 {
		t.Errorf("hosts = %d, want 1", n)
	}
}

// Q12: a second agent claiming a machine-id whose host already has another
// active local agent gets its own host, flagged, never merged.
func TestDuplicateIdentityWithActiveAgentIsFlagged(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	a, b := f.enroll(""), f.enroll("")
	mid := f.machineID()

	ha := f.push(a, HostClaim{MachineID: mid, Hostname: "clone"}).HostID
	rb := f.push(b, HostClaim{MachineID: mid, Hostname: "clone"})
	if !rb.Host.Created || rb.Host.Reattached || rb.HostID == ha || rb.Host.DuplicateOf != ha {
		t.Fatalf("second agent: %+v (A's host %s)", rb.Host, ha)
	}
	var dup string
	if err := f.s.Pool.QueryRow(ctx, `SELECT duplicate_of FROM hosts WHERE id = $1`, rb.HostID).Scan(&dup); err != nil || dup != ha {
		t.Errorf("duplicate_of = %q, %v", dup, err)
	}
	// Stable: both keep pushing to their own host; the identity stays A's.
	for range 2 {
		if got := f.push(b, HostClaim{MachineID: mid}).HostID; got != rb.HostID {
			t.Errorf("B moved to %s", got)
		}
		if got := f.push(a, HostClaim{MachineID: mid}).HostID; got != ha {
			t.Errorf("A moved to %s", got)
		}
	}
	if n := f.count(`SELECT count(*) FROM host_identities WHERE user_id = $1 AND value = $2 AND host_id = $3`, f.userID, mid, ha); n != 1 {
		t.Errorf("identity no longer A's host")
	}
	if n := f.hostsOfUser(); n != 2 {
		t.Errorf("hosts = %d, want 2", n)
	}
}

// Reinstall: the old agent is revoked or no longer active, so the new
// agent re-attaches to the existing host and its history.
func TestReinstallReattaches(t *testing.T) {
	cases := []struct {
		name   string
		retire string // makes the old agent inactive
	}{
		{"revoked", `UPDATE agents SET revoked_at = now() WHERE id = $1`},
		{"silent past default interval", `UPDATE agents SET last_seen_at = now() - interval '46 minutes', push_interval_seconds = NULL WHERE id = $1`},
		{"silent past own interval", `UPDATE agents SET last_seen_at = now() - interval '3 minutes', push_interval_seconds = 30 WHERE id = $1`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAgentFixture(t)
			ctx := context.Background()
			old := f.enroll("")
			mid := f.machineID()
			host := f.push(old, HostClaim{MachineID: mid}).HostID
			f.push(old, HostClaim{MachineID: mid})
			if _, err := f.s.Pool.Exec(ctx, tc.retire, old); err != nil {
				t.Fatal(err)
			}

			fresh := f.enroll("")
			res := f.push(fresh, HostClaim{MachineID: mid})
			if !res.Host.Reattached || res.Host.Created || res.HostID != host {
				t.Fatalf("reinstall: %+v, want re-attach to %s", res.Host, host)
			}
			if got := f.localHost(fresh); got != host {
				t.Errorf("assignment -> %s", got)
			}
			if n := f.count(`SELECT count(*) FROM snapshots WHERE host_id = $1`, host); n != 3 {
				t.Errorf("host history = %d snapshots, want 3", n)
			}
			if n := f.hostsOfUser(); n != 1 {
				t.Errorf("hosts = %d, want 1", n)
			}
		})
	}

	// Control: the old agent seen just now (within 3 x its interval) is
	// active, so the same sequence flags instead.
	f := newAgentFixture(t)
	old := f.enroll("")
	mid := f.machineID()
	host := f.push(old, HostClaim{MachineID: mid}).HostID
	if res := f.push(f.enroll(""), HostClaim{MachineID: mid}); res.Host.Reattached || res.Host.DuplicateOf != host {
		t.Errorf("active old agent: %+v", res.Host)
	}
}

// No identity (empty machine-id, or an agent without a host block): the
// agent's first push creates a host keyed to the agent, later pushes reuse
// it, and a machine-id that appears later is attached to that host.
func TestNoIdentityFallbackIsStable(t *testing.T) {
	f := newAgentFixture(t)
	a := f.enroll("")
	first := f.push(a, HostClaim{Ref: "local", Hostname: "no-mid"})
	if !first.Host.Created {
		t.Fatalf("first push: %+v", first.Host)
	}
	for range 3 {
		if res := f.push(a, HostClaim{}); res.HostID != first.HostID || res.Host.Created {
			t.Fatalf("push moved/created: %+v", res.Host)
		}
	}
	mid := f.machineID()
	if res := f.push(a, HostClaim{MachineID: mid}); res.HostID != first.HostID {
		t.Fatalf("identity push moved host")
	}
	if n := f.count(`SELECT count(*) FROM host_identities WHERE host_id = $1 AND value = $2`, first.HostID, mid); n != 1 {
		t.Errorf("late identity not attached")
	}
	if n := f.hostsOfUser(); n != 1 {
		t.Errorf("hosts = %d, want 1", n)
	}
	// Two agents without identity never share a host.
	if res := f.push(f.enroll(""), HostClaim{}); !res.Host.Created || res.HostID == first.HostID {
		t.Errorf("second no-identity agent: %+v", res.Host)
	}
}

// An agent backfilled by migration 0008 (agents.id = hosts.id, one local
// assignment, credential re-keyed) keeps pushing to its old host, with or
// without a host block, and a later identity attaches to that host.
func TestBackfilledAgentKeepsItsHost(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	hostID, err := f.s.CreateHost(ctx, f.userID, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	// What 0008's backfill does for every pre-existing host.
	for _, q := range []string{
		`INSERT INTO agents (id, user_id, name) SELECT id, user_id, hostname FROM hosts WHERE id = $1`,
		`INSERT INTO agent_credentials (agent_id, secret_hash) VALUES ($1, 'legacy-hash')`,
		`INSERT INTO agent_hosts (agent_id, host_id, mode, target_ref) VALUES ($1, $1, 'local', 'local')`,
	} {
		if _, err := f.s.Pool.Exec(ctx, q, hostID); err != nil {
			t.Fatal(err)
		}
	}
	if res := f.push(hostID, HostClaim{}); res.HostID != hostID || res.Host.Created {
		t.Fatalf("legacy push: %+v", res.Host)
	}
	mid := f.machineID()
	if res := f.push(hostID, HostClaim{MachineID: mid, Hostname: "legacy-real"}); res.HostID != hostID {
		t.Fatalf("identity push: %+v", res.Host)
	}
	if n := f.count(`SELECT count(*) FROM host_identities WHERE host_id = $1`, hostID); n != 1 {
		t.Errorf("identity not attached to legacy host")
	}
	if n := f.hostsOfUser(); n != 1 {
		t.Errorf("hosts = %d, want 1", n)
	}
}

func TestUnknownRemoteRefIsRejected(t *testing.T) {
	f := newAgentFixture(t)
	a := f.enroll("")
	if _, err := f.tryPush(a, HostClaim{Ref: "db-01"}); !errors.Is(err, ErrUnknownHostRef) {
		t.Fatalf("err = %v, want ErrUnknownHostRef", err)
	}
	if n := f.hostsOfUser(); n != 0 {
		t.Errorf("remote ref created %d hosts", n)
	}
}
