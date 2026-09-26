package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/inventory"
)

type SnapshotInput struct {
	HostID         string
	SchemaVersion  int
	CollectedAt    time.Time
	OSID           string
	OSVersionID    string
	OSCodename     string
	RebootRequired bool
	RebootPackages []string
	SourceIP       string
	PublicIPv4     string
	PublicIPv6     string
	// Packages are the legacy snapshot_packages rows (deb only). Still
	// written until DOMAIN_MODEL.md Q6 is decided; host_software is the
	// inventory of record.
	Packages         []PackageInput
	ListeningSockets []SocketInput

	// CollectorStatus is the payload's collectors map as JSON, stored
	// verbatim in snapshots.collector_status. nil = not reported (older
	// agent), stored as NULL.
	CollectorStatus json.RawMessage

	// Inventory holds one authoritative Set per ecosystem (built by
	// ingest.planInventory). Ecosystems not present here are not diffed.
	Inventory []inventory.Set
	// InventoryAt is the range boundary for this push: collected_at,
	// clamped by the caller to no later than the server's clock.
	InventoryAt time.Time
}

// SnapshotResult reports what InsertSnapshot did, for logging and tests.
type SnapshotResult struct {
	SnapshotID string
	Inventory  []InventoryResult
}

type PackageInput struct {
	Name, Version, Arch string
}

type SocketInput struct {
	Proto, LocalAddr, ProcessName string
	Port, PID                     int
	IsPublic                      bool
}

// InsertSnapshot writes a full snapshot (packages, sockets) and applies its
// package inventory to host_software, all in one transaction. It keeps
// every historical snapshot rather than upserting the latest, so drift and
// findings history stay auditable.
//
// The host row is locked first (FOR NO KEY UPDATE), so concurrent pushes
// for one host serialise: each sees the previous one's ranges and state.
// Pushes for different hosts don't contend except on shared
// software_versions rows, which are interned in a fixed order.
func (s *Store) InsertSnapshot(ctx context.Context, in SnapshotInput) (res SnapshotResult, err error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx)

	var locked string
	if err := tx.QueryRow(ctx, `SELECT id FROM hosts WHERE id = $1 FOR NO KEY UPDATE`, in.HostID).Scan(&locked); err != nil {
		return res, fmt.Errorf("lock host: %w", err)
	}

	var hashes []byte // snapshots.package_set_hashes: {"deb": "<hex>"}, NULL if none
	if len(in.Inventory) > 0 {
		m := make(map[string]string, len(in.Inventory))
		for _, set := range in.Inventory {
			m[set.Ecosystem] = set.Hash
		}
		if hashes, err = json.Marshal(m); err != nil {
			return res, err
		}
	}
	var collectorStatus any
	if len(in.CollectorStatus) > 0 {
		collectorStatus = string(in.CollectorStatus)
	}

	// pgx encodes a nil []string as SQL NULL, not as an empty array, which
	// bypasses the column's `DEFAULT '{}'` (defaults only apply when a
	// column is omitted from the INSERT, not when NULL is passed
	// explicitly) and trips its NOT NULL constraint. The agent leaves this
	// nil whenever no reboot is pending, which is the common case.
	rebootPackages := in.RebootPackages
	if rebootPackages == nil {
		rebootPackages = []string{}
	}

	var snapshotID string
	err = tx.QueryRow(ctx, `
		INSERT INTO snapshots (
			host_id, schema_version, collected_at, os_id, os_version_id,
			os_codename, reboot_required, reboot_packages, source_ip,
			public_ipv4, public_ipv6, collector_status, package_set_hashes
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, '')::inet,
			NULLIF($10, '')::inet, NULLIF($11, '')::inet, $12::jsonb, $13::jsonb)
		RETURNING id
	`, in.HostID, in.SchemaVersion, in.CollectedAt, in.OSID, in.OSVersionID, in.OSCodename,
		in.RebootRequired, rebootPackages, in.SourceIP,
		in.PublicIPv4, in.PublicIPv6, collectorStatus, nullableJSON(hashes)).Scan(&snapshotID)
	if err != nil {
		return res, err
	}
	res.SnapshotID = snapshotID

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
			return res, err
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
			return res, err
		}
	}

	for _, set := range in.Inventory {
		r, err := applyInventory(ctx, tx, in.HostID, snapshotID, in.InventoryAt, set)
		if err != nil {
			return res, fmt.Errorf("apply %s inventory: %w", set.Ecosystem, err)
		}
		res.Inventory = append(res.Inventory, r)
	}

	if err := tx.Commit(ctx); err != nil {
		return res, err
	}
	return res, nil
}

func nullableJSON(b []byte) any {
	if b == nil {
		return nil
	}
	return string(b)
}

func nullableInt(v int) any {
	if v == 0 {
		return nil
	}
	return v
}
