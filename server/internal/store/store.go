// Package store is the Postgres access layer for the ingest API. It is
// intentionally thin — no ORM, plain SQL via pgx — since the schema and
// query set are both small and the queries are performance-sensitive
// (snapshot ingest runs on every agent push).
package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	Pool *pgxpool.Pool
}

func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, err
	}
	return &Store{Pool: pool}, nil
}

func (s *Store) Close() {
	s.Pool.Close()
}

type Host struct {
	ID     string
	UserID string
}

// ConsumeEnrollmentToken atomically validates and deletes a one-time
// enrollment token, returning the owning user. Returns pgx.ErrNoRows if
// the token is missing, expired, or already used.
func (s *Store) ConsumeEnrollmentToken(ctx context.Context, token string) (userID string, err error) {
	err = s.Pool.QueryRow(ctx, `
		DELETE FROM enrollment_tokens
		WHERE token = $1 AND expires_at > now()
		RETURNING user_id
	`, token).Scan(&userID)
	return userID, err
}

// CreateHost registers a new host for a user and returns its id.
func (s *Store) CreateHost(ctx context.Context, userID, hostname string) (hostID string, err error) {
	err = s.Pool.QueryRow(ctx, `
		INSERT INTO hosts (user_id, hostname) VALUES ($1, $2) RETURNING id
	`, userID, hostname).Scan(&hostID)
	return hostID, err
}

func (s *Store) StoreAgentSecretHash(ctx context.Context, hostID, secretHash string) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO agent_credentials (host_id, secret_hash) VALUES ($1, $2)
	`, hostID, secretHash)
	return err
}

// AgentSecretHash returns the stored hash for a host's agent credential.
func (s *Store) AgentSecretHash(ctx context.Context, hostID string) (hash string, err error) {
	err = s.Pool.QueryRow(ctx, `
		SELECT secret_hash FROM agent_credentials WHERE host_id = $1
	`, hostID).Scan(&hash)
	return hash, err
}

func (s *Store) TouchHostLastSeen(ctx context.Context, hostID string, at time.Time) error {
	_, err := s.Pool.Exec(ctx, `UPDATE hosts SET last_seen_at = $2 WHERE id = $1`, hostID, at)
	return err
}
