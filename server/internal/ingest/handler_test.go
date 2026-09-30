package ingest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

func TestHostClaim(t *testing.T) {
	ok := map[string]CollectorStatus{CollectorHostIdentity: {Status: "ok"}, CollectorOS: {Status: "ok"}}
	failed := map[string]CollectorStatus{CollectorHostIdentity: {Status: "error"}, CollectorOS: {Status: "ok"}}
	tests := []struct {
		name string
		p    SnapshotPayload
		want store.HostClaim
	}{
		{"v1 without host block", SnapshotPayload{}, store.HostClaim{Ref: "local"}},
		{"full", SnapshotPayload{Collectors: ok, Host: &Host{Ref: "local", Hostname: " web-1 ",
			Identity: HostIdentity{MachineID: "ABCDEF0123456789abcdef0123456789"}}},
			store.HostClaim{Ref: "local", Hostname: "web-1", MachineID: "abcdef0123456789abcdef0123456789"}},
		{"empty ref is local", SnapshotPayload{Host: &Host{}}, store.HostClaim{Ref: "local"}},
		{"failed identity collector keeps hostname only", SnapshotPayload{Collectors: failed,
			Host: &Host{Ref: "local", Hostname: "h", Identity: HostIdentity{MachineID: "0123"}}},
			store.HostClaim{Ref: "local", Hostname: "h"}},
		{"uninitialized", SnapshotPayload{Host: &Host{Identity: HostIdentity{MachineID: "uninitialized"}}},
			store.HostClaim{Ref: "local"}},
		{"remote ref passes through", SnapshotPayload{Host: &Host{Ref: "db-01"}}, store.HostClaim{Ref: "db-01"}},
	}
	for _, tt := range tests {
		if got := hostClaim(tt.p); got != tt.want {
			t.Errorf("%s: hostClaim = %+v, want %+v", tt.name, got, tt.want)
		}
	}
}

func TestOSFamily(t *testing.T) {
	osFailed := map[string]CollectorStatus{CollectorOS: {Status: "error"}}
	tests := []struct {
		name string
		p    SnapshotPayload
		want string
	}{
		{"v1 without host block, OS known", SnapshotPayload{OS: OSRelease{ID: "debian"}}, "linux"},
		{"v1 without host block, OS unknown", SnapshotPayload{}, ""},
		{"reported", SnapshotPayload{Host: &Host{OSFamily: "windows"}}, "windows"},
		{"bogus", SnapshotPayload{Host: &Host{OSFamily: "plan9"}}, ""},
		{"os collector failed", SnapshotPayload{Collectors: osFailed, Host: &Host{OSFamily: "linux"}}, ""},
	}
	for _, tt := range tests {
		if got := osFamily(tt.p); got != tt.want {
			t.Errorf("%s: osFamily = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestAgentReport(t *testing.T) {
	if got := agentReport(SnapshotPayload{}); got != (store.AgentReport{}) {
		t.Errorf("no agent block: %+v", got)
	}
	got := agentReport(SnapshotPayload{Agent: &Agent{Version: "1.0", Platform: "linux/amd64", IntervalSeconds: -5}})
	if got != (store.AgentReport{Version: "1.0", Platform: "linux/amd64"}) {
		t.Errorf("agent block: %+v", got)
	}
}

// End to end over HTTP against a migrated database: enroll creates an agent
// (no host), a v1 push without a host block creates the agent's local host,
// the next push reuses it, and a revoked agent is refused.
func TestEnrollAndPushHTTP(t *testing.T) {
	dsn := os.Getenv("SW_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SW_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	tag := "swtest-" + hex.EncodeToString(b)
	var workspaceID string
	if err := s.Pool.QueryRow(ctx, `INSERT INTO workspaces (name) VALUES ($1) RETURNING id`,
		tag+"@test.invalid").Scan(&workspaceID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.Pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id = $1`, workspaceID)
		s.Close()
	})
	if _, err := s.Pool.Exec(ctx, `INSERT INTO enrollment_tokens (token, workspace_id, expires_at) VALUES ($1, $2, now() + interval '1 hour')`,
		tag, workspaceID); err != nil {
		t.Fatal(err)
	}

	h := &Handler{Store: s}
	do := func(handler http.HandlerFunc, body any, headers map[string]string) *httptest.ResponseRecorder {
		j, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(j))
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		handler(rec, req)
		return rec
	}

	rec := do(h.Enroll, enrollRequest{EnrollmentToken: tag, Hostname: "c0ffee", Version: "1.2.3", Platform: "linux/amd64"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body)
	}
	var creds enrollResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &creds); err != nil || creds.AgentID == "" || creds.AgentSecret == "" {
		t.Fatalf("enroll response %s: %v", rec.Body, err)
	}
	var hosts int
	_ = s.Pool.QueryRow(ctx, `SELECT count(*) FROM hosts WHERE workspace_id = $1`, workspaceID).Scan(&hosts)
	if hosts != 0 {
		t.Fatalf("enroll created %d hosts", hosts)
	}

	auth := map[string]string{"X-Agent-ID": creds.AgentID, "Authorization": "Bearer " + creds.AgentSecret}
	v1 := map[string]any{"schema_version": 1, "collected_at": time.Now().UTC().Format(time.RFC3339),
		"os": map[string]any{"id": "ubuntu", "version_id": "22.04", "codename": "jammy"}}
	for i := range 2 {
		if rec := do(h.Snapshot, v1, auth); rec.Code != http.StatusAccepted {
			t.Fatalf("push %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	var hostname, fam string
	if err := s.Pool.QueryRow(ctx, `
		SELECT h.hostname, h.os_family FROM hosts h JOIN agent_hosts ah ON ah.host_id = h.id
		WHERE ah.agent_id = $1 AND ah.mode = 'local'`, creds.AgentID).Scan(&hostname, &fam); err != nil {
		t.Fatal(err)
	}
	_ = s.Pool.QueryRow(ctx, `SELECT count(*) FROM hosts WHERE workspace_id = $1`, workspaceID).Scan(&hosts)
	if hosts != 1 || hostname != "c0ffee" || fam != "linux" {
		t.Errorf("after v1 pushes: %d hosts, hostname %q, family %q", hosts, hostname, fam)
	}

	if rec := do(h.Snapshot, v1, map[string]string{"X-Agent-ID": creds.AgentID, "Authorization": "Bearer wrong"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("bad secret: %d", rec.Code)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE agents SET revoked_at = now() WHERE id = $1`, creds.AgentID); err != nil {
		t.Fatal(err)
	}
	if rec := do(h.Snapshot, v1, auth); rec.Code != http.StatusUnauthorized {
		t.Errorf("revoked agent: %d", rec.Code)
	}
}
