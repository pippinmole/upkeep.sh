package store

// Credential rotation and cleanup (migration 0011). Skipped unless
// SW_TEST_DATABASE_URL is set.

import (
	"context"
	"errors"
	"testing"
	"time"
)

func (f *agentFixture) cred(agentID string) AgentCredential {
	f.t.Helper()
	c, err := f.s.AgentCredential(context.Background(), agentID)
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

func TestRotateFromCurrentKeepsPreviousForGrace(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	id := f.enroll("") // secret hash "hash"
	if _, err := f.s.Pool.Exec(ctx, `UPDATE agent_credentials SET rotate_requested_at = now() WHERE agent_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if c := f.cred(id); !c.RotateRequested || c.PreviousSecretHash != "" {
		t.Fatalf("before: %+v", c)
	}

	if err := f.s.RotateAgentCredential(ctx, id, "hash", "h1", time.Hour); err != nil {
		t.Fatal(err)
	}
	c := f.cred(id)
	if c.SecretHash != "h1" || c.PreviousSecretHash != "hash" || c.RotateRequested || time.Since(c.IssuedAt) > time.Minute {
		t.Fatalf("after rotate: %+v", c)
	}

	// The agent lost h1 (crash before persisting) and rotates again with
	// the previous secret: allowed in the window, h1 is replaced, and the
	// previous secret's expiry is NOT extended.
	var exp1 time.Time
	_ = f.s.Pool.QueryRow(ctx, `SELECT previous_expires_at FROM agent_credentials WHERE agent_id = $1`, id).Scan(&exp1)
	if err := f.s.RotateAgentCredential(ctx, id, "hash", "h2", 10*time.Hour); err != nil {
		t.Fatal(err)
	}
	var exp2 time.Time
	_ = f.s.Pool.QueryRow(ctx, `SELECT previous_expires_at FROM agent_credentials WHERE agent_id = $1`, id).Scan(&exp2)
	if c := f.cred(id); c.SecretHash != "h2" || c.PreviousSecretHash != "hash" || !exp1.Equal(exp2) {
		t.Fatalf("rotate from previous: %+v, expiry %v -> %v", c, exp1, exp2)
	}
	// The lost secret is gone for good.
	if err := f.s.RotateAgentCredential(ctx, id, "h1", "h3", time.Hour); !errors.Is(err, ErrInvalidCredential) {
		t.Errorf("rotated-away secret: %v", err)
	}

	// First use of the new secret ends the window early.
	if err := f.s.ConfirmRotation(ctx, id); err != nil {
		t.Fatal(err)
	}
	if c := f.cred(id); c.PreviousSecretHash != "" {
		t.Errorf("after confirm: previous still %q", c.PreviousSecretHash)
	}
	if err := f.s.RotateAgentCredential(ctx, id, "hash", "h4", time.Hour); !errors.Is(err, ErrInvalidCredential) {
		t.Errorf("previous after confirm: %v", err)
	}
}

func TestPreviousSecretExpiresAfterGrace(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	id := f.enroll("")
	if err := f.s.RotateAgentCredential(ctx, id, "hash", "h1", time.Hour); err != nil {
		t.Fatal(err)
	}
	// Grace over.
	if _, err := f.s.Pool.Exec(ctx, `UPDATE agent_credentials SET previous_expires_at = now() - interval '1 second' WHERE agent_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if c := f.cred(id); c.PreviousSecretHash != "" {
		t.Errorf("expired previous still returned: %+v", c)
	}
	if err := f.s.RotateAgentCredential(ctx, id, "hash", "h2", time.Hour); !errors.Is(err, ErrInvalidCredential) {
		t.Errorf("replay after grace: %v", err)
	}
	if c := f.cred(id); c.SecretHash != "h1" {
		t.Errorf("secret changed by a refused rotation: %+v", c)
	}
	if err := f.s.RotateAgentCredential(ctx, id, "", "h2", time.Hour); !errors.Is(err, ErrInvalidCredential) {
		t.Errorf("empty presented hash: %v", err)
	}

	// Cleanup clears the expired previous hash (and expired tokens only).
	if _, err := f.s.Pool.Exec(ctx, `INSERT INTO enrollment_tokens (token, workspace_id, expires_at) VALUES
		($1 || '-old', $2, now() - interval '1 minute'), ($1 || '-new', $2, now() + interval '1 hour')`, f.tag, f.workspaceID); err != nil {
		t.Fatal(err)
	}
	r, err := f.s.CleanupCredentials(ctx)
	if err != nil || r.EnrollmentTokens < 1 || r.PreviousSecrets < 1 {
		t.Fatalf("cleanup: %+v, %v", r, err)
	}
	if n := f.count(`SELECT count(*) FROM enrollment_tokens WHERE workspace_id = $1`, f.workspaceID); n != 1 {
		t.Errorf("tokens left = %d, want the unexpired one", n)
	}
	if n := f.count(`SELECT count(*) FROM agent_credentials WHERE agent_id = $1 AND previous_secret_hash IS NULL`, id); n != 1 {
		t.Errorf("expired previous hash not cleared")
	}
}

func TestRotateRevokedAgent(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	id := f.enroll("")
	if st := f.mgmt(`SELECT mgmt_revoke_agent($1, $2)`, f.workspaceID, id); st != "ok" {
		t.Fatalf("revoke: %s", st)
	}
	if err := f.s.RotateAgentCredential(ctx, id, "hash", "h1", time.Hour); !errors.Is(err, ErrAgentRevoked) {
		t.Errorf("rotate revoked: %v", err)
	}
	if err := f.s.RotateAgentCredential(ctx, "00000000-0000-0000-0000-000000000000", "hash", "h1", time.Hour); !errors.Is(err, ErrInvalidCredential) {
		t.Errorf("rotate unknown agent: %v", err)
	}
}
