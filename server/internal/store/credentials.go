package store

// Agent credentials: authentication, rotation and cleanup (PROTOCOL.md
// "Credential rotation", migration 0011).
//
// An agent_credentials row holds the current secret's hash and, for a
// short grace window after a rotation, the previous one. Rotation is
// agent-initiated: the server only signals it (a response header on the
// snapshot push), the agent calls POST /v1/agent/rotate. The grace window
// covers an agent that crashes after receiving the new secret but before
// persisting it: it comes back with the old one, is accepted, told to
// rotate again, and does. The previous secret stops working at the end of
// the window, or as soon as the new secret is first used.

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrInvalidCredential: the presented secret matches neither the current
// secret nor an unexpired previous one (or the agent doesn't exist).
var ErrInvalidCredential = errors.New("invalid credential")

// ErrAgentRevoked: the agent was revoked in the dashboard.
var ErrAgentRevoked = errors.New("agent revoked")

// AgentCredential is what agent authentication needs.
type AgentCredential struct {
	WorkspaceID string
	SecretHash  string
	// PreviousSecretHash is the pre-rotation secret's hash while its grace
	// window is open, else "".
	PreviousSecretHash string
	Revoked            bool
	// RotateRequested: the dashboard asked for a rotation that hasn't
	// happened yet.
	RotateRequested bool
	// IssuedAt is when the current secret was issued (last rotation, else
	// enrollment).
	IssuedAt time.Time
}

// AgentCredential returns the stored credential of an agent.
func (s *Store) AgentCredential(ctx context.Context, agentID string) (c AgentCredential, err error) {
	var prev *string
	err = s.Pool.QueryRow(ctx, `
		SELECT a.workspace_id, c.secret_hash,
		       CASE WHEN c.previous_expires_at > now() THEN c.previous_secret_hash END,
		       a.revoked_at IS NOT NULL, c.rotate_requested_at IS NOT NULL,
		       COALESCE(c.rotated_at, c.created_at)
		FROM agent_credentials c JOIN agents a ON a.id = c.agent_id
		WHERE c.agent_id = $1
	`, agentID).Scan(&c.WorkspaceID, &c.SecretHash, &prev, &c.Revoked, &c.RotateRequested, &c.IssuedAt)
	if prev != nil {
		c.PreviousSecretHash = *prev
	}
	return c, err
}

// ConfirmRotation ends the previous secret's grace window early: called
// when the agent authenticates with its current secret, which proves it
// persisted it.
func (s *Store) ConfirmRotation(ctx context.Context, agentID string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE agent_credentials SET previous_secret_hash = NULL, previous_expires_at = NULL
		WHERE agent_id = $1 AND previous_secret_hash IS NOT NULL
	`, agentID)
	return err
}

// RotateAgentCredential replaces an agent's secret with newHash.
// presentedHash is the stored hash the caller's secret matched (the
// handler verifies the secret in constant time against the hashes from
// AgentCredential); it is re-checked here under a row lock, so concurrent
// rotations serialize and a secret that was rotated away in between is
// refused.
//
//   - presented = current: the current secret becomes the previous one,
//     valid for grace.
//   - presented = previous (still in its window; the agent lost the secret
//     of the last rotation): the previous secret and its original expiry
//     are kept, so repeated rotations never extend it; the lost secret is
//     simply replaced.
//
// Clears rotate_requested_at and sets rotated_at.
func (s *Store) RotateAgentCredential(ctx context.Context, agentID, presentedHash, newHash string, grace time.Duration) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var current string
	var prev *string
	var prevValid, revoked bool
	err = tx.QueryRow(ctx, `
		SELECT c.secret_hash, c.previous_secret_hash, COALESCE(c.previous_expires_at > now(), false),
		       a.revoked_at IS NOT NULL
		FROM agent_credentials c JOIN agents a ON a.id = c.agent_id
		WHERE c.agent_id = $1
		FOR UPDATE OF c
	`, agentID).Scan(&current, &prev, &prevValid, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalidCredential
	} else if err != nil {
		return err
	}
	if revoked {
		return ErrAgentRevoked
	}
	switch {
	case presentedHash != "" && presentedHash == current:
		_, err = tx.Exec(ctx, `
			UPDATE agent_credentials
			SET secret_hash = $2, previous_secret_hash = secret_hash,
			    previous_expires_at = now() + make_interval(secs => $3),
			    rotated_at = now(), rotate_requested_at = NULL
			WHERE agent_id = $1
		`, agentID, newHash, grace.Seconds())
	case presentedHash != "" && prev != nil && prevValid && presentedHash == *prev:
		_, err = tx.Exec(ctx, `
			UPDATE agent_credentials SET secret_hash = $2, rotated_at = now(), rotate_requested_at = NULL
			WHERE agent_id = $1
		`, agentID, newHash)
	default:
		return ErrInvalidCredential
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// CleanupResult is what CleanupCredentials removed.
type CleanupResult struct {
	EnrollmentTokens int64 // expired, never-used enrollment tokens deleted
	PreviousSecrets  int64 // expired grace-window secrets cleared
}

// CleanupCredentials deletes expired enrollment tokens and clears expired
// previous-secret hashes. Neither is a security issue left in place (both
// are checked against their expiry); they are just dead rows.
func (s *Store) CleanupCredentials(ctx context.Context) (r CleanupResult, err error) {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM enrollment_tokens WHERE expires_at <= now()`)
	if err != nil {
		return r, err
	}
	r.EnrollmentTokens = tag.RowsAffected()
	tag, err = s.Pool.Exec(ctx, `
		UPDATE agent_credentials SET previous_secret_hash = NULL, previous_expires_at = NULL
		WHERE previous_expires_at <= now()
	`)
	if err != nil {
		return r, err
	}
	r.PreviousSecrets = tag.RowsAffected()
	return r, nil
}
