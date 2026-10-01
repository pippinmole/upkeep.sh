package store

// Remote targets (migration 0012): adding a remote host, the agent's
// config, status reports and host key confirmation, and pushes for a
// remote ref. Skipped unless SW_TEST_DATABASE_URL is set.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const (
	testAgentKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDOgzQA+0gYe3bNWRpmy4dc9UnFnDWFNyKwS53m2CEb3"
	testHostKey  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHv0dGVzdC1ob3N0LWtleS0wMDAwMDAwMDAwMDAwMDAw"
	otherHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG90aGVyLWhvc3Qta2V5LTAwMDAwMDAwMDAwMDAwMDA"
)

// addRemote adds an ssh target for agentID and returns the new host id.
func (f *agentFixture) addRemote(agentID, address string) string {
	f.t.Helper()
	st := f.mgmt(`SELECT mgmt_add_remote_host($1, $2, $3, 22, 'upkeep', '')`, f.workspaceID, agentID, address)
	id, ok := strings.CutPrefix(st, "ok:")
	if !ok {
		f.t.Fatalf("mgmt_add_remote_host: %s", st)
	}
	return id
}

func (f *agentFixture) reportStatus(agentID string, rep StatusReport) {
	f.t.Helper()
	if err := f.s.RecordAgentStatus(context.Background(), agentID, rep); err != nil {
		f.t.Fatal(err)
	}
}

func (f *agentFixture) target(agentID, hostID string) (hostKey, pending, code *string) {
	f.t.Helper()
	if err := f.s.Pool.QueryRow(context.Background(), `
		SELECT host_key, host_key_pending, last_error_code FROM agent_hosts WHERE agent_id = $1 AND host_id = $2
	`, agentID, hostID).Scan(&hostKey, &pending, &code); err != nil {
		f.t.Fatal(err)
	}
	return hostKey, pending, code
}

func str(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

func TestRemoteHostLifecycle(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	a := f.enroll("")

	// A host can be added before the agent has reported its ssh key (it
	// may not have started yet); the dashboard waits for the key.
	if st := f.mgmt(`SELECT mgmt_add_remote_host($1, $2, '10.0.0.5', 22, 'upkeep', '')`, f.workspaceID, f.enroll("")); !strings.HasPrefix(st, "ok:") {
		t.Fatalf("add before key: %s", st)
	}
	f.reportStatus(a, StatusReport{SSHPublicKey: testAgentKey})

	for _, c := range []struct{ addr, user, want string }{
		{"-oProxyCommand=x", "upkeep", "invalid_address"},
		{"10.0.0.5 extra", "upkeep", "invalid_address"},
		{"root@10.0.0.5", "upkeep", "invalid_address"},
		{"10.0.0.5", "Root;", "invalid_username"},
	} {
		if st := f.mgmt(`SELECT mgmt_add_remote_host($1, $2, $3, 22, $4, '')`, f.workspaceID, a, c.addr, c.user); st != c.want {
			t.Errorf("add %q/%q: %s, want %s", c.addr, c.user, st, c.want)
		}
	}

	h := f.addRemote(a, "DB-1.internal")
	if st := f.mgmt(`SELECT mgmt_add_remote_host($1, $2, 'db-1.internal', 22, 'x', '')`, f.workspaceID, a); st != "duplicate_target" {
		t.Errorf("duplicate add: %s", st)
	}

	cfg, err := f.s.AgentConfig(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Targets) != 1 || cfg.Targets[0].Ref != h || cfg.Targets[0].Address != "db-1.internal" ||
		cfg.Targets[0].HostKey != "" || cfg.Targets[0].Username != "upkeep" {
		t.Fatalf("config: %+v", cfg)
	}
	v1 := cfg.Version

	// The agent fetches the host key without authenticating and reports it.
	f.reportStatus(a, StatusReport{Targets: []TargetStatus{{Ref: h, ErrorCode: TargetHostKeyUnconfirmed, Error: "confirm", PresentedHostKey: testHostKey}}})
	if k, p, c := f.target(a, h); k != nil || str(p) != testHostKey || str(c) != TargetHostKeyUnconfirmed {
		t.Fatalf("after probe: key=%s pending=%s code=%s", str(k), str(p), str(c))
	}

	// Confirming a key other than the pending one is refused.
	if st := f.mgmt(`SELECT mgmt_confirm_host_key($1, $2, $3, $4)`, f.workspaceID, a, h, otherHostKey); st != "host_key_changed" {
		t.Fatalf("confirm wrong key: %s", st)
	}
	if st := f.mgmt(`SELECT mgmt_confirm_host_key($1, $2, $3, $4)`, f.workspaceID, a, h, testHostKey); st != "ok" {
		t.Fatalf("confirm: %s", st)
	}
	cfg, _ = f.s.AgentConfig(ctx, a)
	if cfg.Targets[0].HostKey != testHostKey || cfg.Version == v1 {
		t.Fatalf("config after confirm: %+v", cfg)
	}

	// A stale probe result (config fetched before the confirmation) doesn't
	// resurrect the error.
	f.reportStatus(a, StatusReport{Targets: []TargetStatus{{Ref: h, ErrorCode: TargetHostKeyUnconfirmed, PresentedHostKey: testHostKey}}})
	if k, p, c := f.target(a, h); str(k) != testHostKey || p != nil || c != nil {
		t.Fatalf("after stale report: key=%s pending=%s code=%s", str(k), str(p), str(c))
	}

	// The push for the remote ref lands on the pre-created host, and the
	// hostname becomes what the machine reports.
	res := f.push(a, HostClaim{Ref: h, MachineID: f.machineID(), Hostname: "db-1"})
	if res.HostID != h || res.Host.Created {
		t.Fatalf("remote push: %+v", res.Host)
	}
	if n := f.count(`SELECT count(*) FROM hosts WHERE id = $1 AND hostname = 'db-1'`, h); n != 1 {
		t.Fatal("hostname not updated from the push")
	}
	// The agent's own machine is still its local host, separately.
	local := f.push(a, HostClaim{MachineID: f.machineID(), Hostname: "agent-box"})
	if local.HostID == h || !local.Host.Created {
		t.Fatalf("local push: %+v", local.Host)
	}

	// The host key changes: the agent reports a mismatch, the new key is
	// pending, the confirmed one stays until the user accepts the change.
	f.reportStatus(a, StatusReport{Targets: []TargetStatus{{Ref: h, ErrorCode: TargetHostKeyMismatch, PresentedHostKey: otherHostKey}}})
	if k, p, c := f.target(a, h); str(k) != testHostKey || str(p) != otherHostKey || str(c) != TargetHostKeyMismatch {
		t.Fatalf("after mismatch: key=%s pending=%s code=%s", str(k), str(p), str(c))
	}

	// Another user can't confirm keys or remove targets.
	other := f.otherUser()
	if st := f.mgmt(`SELECT mgmt_confirm_host_key($1, $2, $3, $4)`, other, a, h, otherHostKey); st != "not_found" {
		t.Errorf("cross-tenant confirm: %s", st)
	}
	if st := f.mgmt(`SELECT mgmt_remove_remote_target($1, $2, $3)`, other, a, h); st != "not_found" {
		t.Errorf("cross-tenant remove: %s", st)
	}
	if st := f.mgmt(`SELECT mgmt_add_remote_host($1, $2, '10.9.9.9', 22, 'upkeep', '')`, other, a); st != "not_found" {
		t.Errorf("cross-tenant add: %s", st)
	}

	// Removing the target (agent still active) stops pushes for its ref.
	if st := f.mgmt(`SELECT mgmt_remove_remote_target($1, $2, $3)`, f.workspaceID, a, h); st != "ok" {
		t.Fatalf("remove: %s", st)
	}
	if _, err := f.tryPush(a, HostClaim{Ref: h}); !errors.Is(err, ErrUnknownHostRef) {
		t.Fatalf("push after remove: %v", err)
	}
	// The local assignment can't be removed this way.
	if st := f.mgmt(`SELECT mgmt_remove_remote_target($1, $2, $3)`, f.workspaceID, a, local.HostID); st != "not_found" {
		t.Errorf("remove local: %s", st)
	}
}
