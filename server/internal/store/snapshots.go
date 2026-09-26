package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

type SnapshotInput struct {
	HostID           string
	CollectedAt      time.Time
	OSID             string
	OSVersionID      string
	OSCodename       string
	RebootRequired   bool
	RebootPackages   []string
	SourceIP         string
	PublicIPv4       string
	PublicIPv6       string
	Packages         []PackageInput
	ListeningSockets []SocketInput
}

type PackageInput struct {
	Name, Version, Arch string
}

type SocketInput struct {
	Proto, LocalAddr, ProcessName string
	Port, PID                     int
	IsPublic                      bool
}

// InsertSnapshot writes a full snapshot (packages, sockets) in one
// transaction. It intentionally keeps every historical snapshot rather
// than upserting the latest, so drift and findings history stay auditable.
func (s *Store) InsertSnapshot(ctx context.Context, in SnapshotInput) (snapshotID string, err error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	// pgx encodes a nil []string as SQL NULL, not as an empty array, which
	// bypasses the column's `DEFAULT '{}'` (defaults only apply when a
	// column is omitted from the INSERT, not when NULL is passed
	// explicitly) and trips its NOT NULL constraint. The agent leaves this
	// nil whenever no reboot is pending, which is the common case.
	rebootPackages := in.RebootPackages
	if rebootPackages == nil {
		rebootPackages = []string{}
	}

	err = tx.QueryRow(ctx, `
		INSERT INTO snapshots (
			host_id, schema_version, collected_at, os_id, os_version_id,
			os_codename, reboot_required, reboot_packages, source_ip,
			public_ipv4, public_ipv6
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, '')::inet,
			NULLIF($10, '')::inet, NULLIF($11, '')::inet)
		RETURNING id
	`, in.HostID, 1, in.CollectedAt, in.OSID, in.OSVersionID, in.OSCodename,
		in.RebootRequired, rebootPackages, in.SourceIP,
		in.PublicIPv4, in.PublicIPv6).Scan(&snapshotID)
	if err != nil {
		return "", err
	}

	pkgRows := make([][]any, len(in.Packages))
	for i, p := range in.Packages {
		pkgRows[i] = []any{snapshotID, p.Name, p.Version, p.Arch}
	}
	if len(pkgRows) > 0 {
		if _, err := tx.CopyFrom(ctx,
			pgx.Identifier{"snapshot_packages"},
			[]string{"snapshot_id", "name", "version", "arch"},
			pgx.CopyFromRows(pkgRows),
		); err != nil {
			return "", err
		}
	}

	sockRows := make([][]any, len(in.ListeningSockets))
	for i, sock := range in.ListeningSockets {
		sockRows[i] = []any{snapshotID, sock.Proto, sock.LocalAddr, sock.Port, nullableInt(sock.PID), sock.ProcessName, sock.IsPublic}
	}
	if len(sockRows) > 0 {
		if _, err := tx.CopyFrom(ctx,
			pgx.Identifier{"listening_sockets"},
			[]string{"snapshot_id", "proto", "local_addr", "port", "pid", "process_name", "is_public"},
			pgx.CopyFromRows(sockRows),
		); err != nil {
			return "", err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return snapshotID, nil
}

func nullableInt(v int) any {
	if v == 0 {
		return nil
	}
	return v
}
