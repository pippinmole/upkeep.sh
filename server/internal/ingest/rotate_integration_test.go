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

type rotateEnv struct {
	t      *testing.T
	s      *store.Store
	h      *Handler
	userID string
	agent  string
}

func newRotateEnv(t *testing.T) (*rotateEnv, string) {
	t.Helper()
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
	e := &rotateEnv{t: t, s: s, h: &Handler{Store: s, RotationGrace: time.Hour}}
	if err := s.Pool.QueryRow(ctx, `INSERT INTO users (email) VALUES ($1) RETURNING id`,
		tag+"@test.invalid").Scan(&e.userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.Pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, e.userID)
		s.Close()
	})
	if _, err := s.Pool.Exec(ctx, `INSERT INTO enrollment_tokens (token, user_id, expires_at) VALUES ($1, $2, now() + interval '1 hour')`,
		tag, e.userID); err != nil {
		t.Fatal(err)
	}
	rec := e.do(e.h.Enroll, "", enrollRequest{EnrollmentToken: tag, Hostname: "rot"})
	var creds enrollResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &creds) != nil {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body)
	}
	e.agent = creds.AgentID
	return e, creds.AgentSecret
}

func (e *rotateEnv) do(handler http.HandlerFunc, secret string, body any) *httptest.ResponseRecorder {
	j, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(j))
	if secret != "" {
		req.Header.Set("X-Agent-ID", e.agent)
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func (e *rotateEnv) push(secret string) *httptest.ResponseRecorder {
	return e.do(e.h.Snapshot, secret, map[string]any{"schema_version": 1,
		"collected_at": time.Now().UTC().Format(time.RFC3339), "os": map[string]any{"id": "debian"}})
}

func (e *rotateEnv) rotate(secret string) (string, int) {
	e.t.Helper()
	rec := e.do(e.h.Rotate, secret, nil)
	if rec.Code != http.StatusOK {
		return "", rec.Code
	}
	var out enrollResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.AgentID != e.agent || out.AgentSecret == "" {
		e.t.Fatalf("rotate response %s: %v", rec.Body, err)
	}
	return out.AgentSecret, rec.Code
}

func (e *rotateEnv) exec(q string) {
	e.t.Helper()
	if _, err := e.s.Pool.Exec(context.Background(), q, e.agent); err != nil {
		e.t.Fatal(err)
	}
}

// Dashboard request -> push signals -> agent rotates -> old secret works
// only in the grace window, and not at all once the new one is used.
func TestRotationFlowHTTP(t *testing.T) {
	e, s0 := newRotateEnv(t)

	if rec := e.push(s0); rec.Code != http.StatusAccepted || rec.Header().Get(RotateHeader) != "" {
		t.Fatalf("plain push: %d, rotate header %q", rec.Code, rec.Header().Get(RotateHeader))
	}
	var st string
	if err := e.s.Pool.QueryRow(context.Background(), `SELECT mgmt_request_rotation($1, $2)`, e.userID, e.agent).Scan(&st); err != nil || st != "ok" {
		t.Fatalf("request rotation: %q %v", st, err)
	}
	if rec := e.push(s0); rec.Code != http.StatusAccepted || rec.Header().Get(RotateHeader) != "1" {
		t.Fatalf("push after request: %d, rotate header %q", rec.Code, rec.Header().Get(RotateHeader))
	}

	s1, code := e.rotate(s0)
	if code != http.StatusOK || s1 == s0 {
		t.Fatalf("rotate: %d", code)
	}
	// Simulated crash before persisting s1: the agent comes back with s0.
	// Accepted (grace), and told to rotate again.
	if rec := e.push(s0); rec.Code != http.StatusAccepted || rec.Header().Get(RotateHeader) != "1" {
		t.Fatalf("push with previous secret in grace: %d, header %q", rec.Code, rec.Header().Get(RotateHeader))
	}
	s2, code := e.rotate(s0)
	if code != http.StatusOK {
		t.Fatalf("rotate with previous secret in grace: %d", code)
	}
	if rec := e.push(s1); rec.Code != http.StatusUnauthorized {
		t.Errorf("lost secret s1 still accepted: %d", rec.Code)
	}
	// s2 persisted and used: request cleared, s0's window closes at once.
	if rec := e.push(s2); rec.Code != http.StatusAccepted || rec.Header().Get(RotateHeader) != "" {
		t.Fatalf("push with new secret: %d, header %q", rec.Code, rec.Header().Get(RotateHeader))
	}
	if rec := e.push(s0); rec.Code != http.StatusUnauthorized {
		t.Errorf("previous secret after the new one was used: %d", rec.Code)
	}
	if _, code := e.rotate(s0); code != http.StatusUnauthorized {
		t.Errorf("rotate with previous secret after confirm: %d", code)
	}
}

// Replay of the pre-rotation secret after the grace window: refused on both
// endpoints, even though the new secret was never used.
func TestRotationReplayAfterGraceHTTP(t *testing.T) {
	e, s0 := newRotateEnv(t)
	s1, code := e.rotate(s0)
	if code != http.StatusOK {
		t.Fatalf("rotate: %d", code)
	}
	e.exec(`UPDATE agent_credentials SET previous_expires_at = now() - interval '1 second' WHERE agent_id = $1`)
	if rec := e.push(s0); rec.Code != http.StatusUnauthorized {
		t.Errorf("push with old secret after grace: %d", rec.Code)
	}
	if _, code := e.rotate(s0); code != http.StatusUnauthorized {
		t.Errorf("rotate with old secret after grace: %d", code)
	}
	if rec := e.push(s1); rec.Code != http.StatusAccepted {
		t.Errorf("current secret: %d", rec.Code)
	}
}

func TestRotationRefusedForRevokedAgentHTTP(t *testing.T) {
	e, s0 := newRotateEnv(t)
	var st string
	if err := e.s.Pool.QueryRow(context.Background(), `SELECT mgmt_revoke_agent($1, $2)`, e.userID, e.agent).Scan(&st); err != nil || st != "ok" {
		t.Fatalf("revoke: %q %v", st, err)
	}
	if _, code := e.rotate(s0); code != http.StatusUnauthorized {
		t.Errorf("rotate revoked: %d", code)
	}
	if rec := e.push(s0); rec.Code != http.StatusUnauthorized {
		t.Errorf("push revoked: %d", rec.Code)
	}
	if rec := e.do(e.h.Rotate, "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("rotate without credentials: %d", rec.Code)
	}
}

// Periodic rotation: a secret older than CredentialMaxAge is told to rotate.
func TestPeriodicRotationSignalHTTP(t *testing.T) {
	e, s0 := newRotateEnv(t)
	e.h.CredentialMaxAge = 24 * time.Hour
	if rec := e.push(s0); rec.Header().Get(RotateHeader) != "" {
		t.Error("fresh secret told to rotate")
	}
	e.exec(`UPDATE agent_credentials SET created_at = now() - interval '2 days' WHERE agent_id = $1`)
	if rec := e.push(s0); rec.Code != http.StatusAccepted || rec.Header().Get(RotateHeader) != "1" {
		t.Errorf("old secret: %d, header %q", rec.Code, rec.Header().Get(RotateHeader))
	}
	s1, _ := e.rotate(s0)
	if rec := e.push(s1); rec.Header().Get(RotateHeader) != "" {
		t.Error("just-rotated secret told to rotate")
	}
}
