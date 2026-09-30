// Package store is the Postgres access layer for the ingest API. It is
// intentionally thin — no ORM, plain SQL via pgx — since the schema and
// query set are both small and the queries are performance-sensitive
// (snapshot ingest runs on every agent push).
package store

import (
	"context"

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

// CreateHost registers a bare host for a user (no agent, no assignment)
// and returns its id. Ingest never calls it: hosts are created by
// resolveHost on an agent's first push. Tests use it to get a host whose
// snapshots are inserted with SnapshotInput.HostID.
func (s *Store) CreateHost(ctx context.Context, workspaceID, hostname string) (hostID string, err error) {
	err = s.Pool.QueryRow(ctx, `
		INSERT INTO hosts (workspace_id, hostname) VALUES ($1, $2) RETURNING id
	`, workspaceID, hostname).Scan(&hostID)
	return hostID, err
}
