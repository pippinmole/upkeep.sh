package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/inventory"
)

// InventoryOutcome says what applyInventory did for one ecosystem.
type InventoryOutcome string

const (
	// InventoryUnchanged: set hash equal to the host's current hash; only
	// the confirmation timestamp moved. No diff, no interning.
	InventoryUnchanged InventoryOutcome = "unchanged"
	// InventoryDiffed: hash differed (or was unknown); ranges reconciled.
	InventoryDiffed InventoryOutcome = "diffed"
	// InventoryStale: collected no later than the newest inventory already
	// applied for this ecosystem. Snapshot stored, ranges untouched.
	InventoryStale InventoryOutcome = "stale"
)

type InventoryResult struct {
	Ecosystem string
	Outcome   InventoryOutcome
	Added     int // ranges opened
	Removed   int // ranges closed
	// NewSoftwareIDs are software_versions rows first interned by this
	// push: the P1b matcher's "evaluate this version" trigger (§2.6).
	NewSoftwareIDs []int64
	// ResetSoftwareIDs are existing rows whose inferred source was replaced
	// by a real one on this push (matcher bookkeeping reset): also to be
	// (re-)evaluated.
	ResetSoftwareIDs []int64
}

// applyInventory reconciles host_software with one authoritative set.
// Must run inside the snapshot transaction, after the host row is locked.
//
// Invariants maintained:
//   - at most one open range per (host, software_id) (unique partial index)
//   - ranges are only opened/closed for set.Ecosystem; other ecosystems'
//     ranges are never read or written here
//   - range boundaries strictly increase per (host, ecosystem): a push not
//     newer than host_inventory_state.confirmed_at is stale and ignored, so
//     removed_at > first_seen_at always holds (CHECK constraint)
//   - host_inventory_state.package_set_hash is the hash of exactly the set
//     of open ranges for that ecosystem, or NULL when unknown (backfill),
//     which forces the next push to diff
func applyInventory(ctx context.Context, tx pgx.Tx, hostID, snapshotID string, at time.Time, set inventory.Set) (InventoryResult, error) {
	res := InventoryResult{Ecosystem: set.Ecosystem}

	var (
		curHash     *string
		confirmedAt time.Time
		haveState   = true
	)
	err := tx.QueryRow(ctx, `
		SELECT package_set_hash, confirmed_at FROM host_inventory_state
		WHERE host_id = $1 AND ecosystem = $2
	`, hostID, set.Ecosystem).Scan(&curHash, &confirmedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		haveState = false
	} else if err != nil {
		return res, err
	}

	if haveState && !at.After(confirmedAt) {
		res.Outcome = InventoryStale
		return res, nil
	}

	if haveState && curHash != nil && *curHash == set.Hash {
		res.Outcome = InventoryUnchanged
		_, err := tx.Exec(ctx, `
			UPDATE host_inventory_state
			SET confirmed_at = $3, confirmed_snapshot_id = $4
			WHERE host_id = $1 AND ecosystem = $2
		`, hostID, set.Ecosystem, at, snapshotID)
		return res, err
	}

	res.Outcome = InventoryDiffed
	reported, newIDs, resetIDs, err := internVersions(ctx, tx, set)
	if err != nil {
		return res, err
	}
	res.NewSoftwareIDs, res.ResetSoftwareIDs = newIDs, resetIDs

	rows, err := tx.Query(ctx, `
		SELECT hs.software_id
		FROM host_software hs
		JOIN software_versions sv ON sv.id = hs.software_id
		WHERE hs.host_id = $1 AND hs.removed_at IS NULL AND sv.ecosystem = $2
	`, hostID, set.Ecosystem)
	if err != nil {
		return res, err
	}
	open, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return res, err
	}

	added, removed := inventory.Diff(open, reported)
	res.Added, res.Removed = len(added), len(removed)

	if len(removed) > 0 {
		if _, err := tx.Exec(ctx, `
			UPDATE host_software
			SET removed_at = $3, removed_snapshot_id = $4
			WHERE host_id = $1 AND removed_at IS NULL AND software_id = ANY($2::bigint[])
		`, hostID, removed, at, snapshotID); err != nil {
			return res, err
		}
	}
	if len(added) > 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO host_software (host_id, software_id, first_seen_at, first_seen_snapshot_id)
			SELECT $1, id, $3, $4 FROM unnest($2::bigint[]) AS id
		`, hostID, added, at, snapshotID); err != nil {
			return res, err
		}
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO host_inventory_state
			(host_id, ecosystem, package_set_hash, confirmed_at, confirmed_snapshot_id, changed_at)
		VALUES ($1, $2, $3, $4, $5, $4)
		ON CONFLICT (host_id, ecosystem) DO UPDATE SET
			package_set_hash      = EXCLUDED.package_set_hash,
			confirmed_at          = EXCLUDED.confirmed_at,
			confirmed_snapshot_id = EXCLUDED.confirmed_snapshot_id,
			changed_at = CASE WHEN $6 THEN EXCLUDED.changed_at ELSE host_inventory_state.changed_at END
	`, hostID, set.Ecosystem, set.Hash, at, snapshotID, len(added)+len(removed) > 0)
	return res, err
}

// internVersions upserts every item of set into software_versions in one
// statement and returns the ids of all of them (in no particular order),
// the ids that were newly inserted, and the ids whose inferred source was
// replaced. Two round trips regardless of set size.
//
// Source is an attribute, not part of the key: a binary (name, version,
// arch) in one distro release has one source in the archive. The only
// update ever made to an existing row is replacing an inferred source
// (from an older agent or the backfill) with a real one; that resets the
// matcher bookkeeping so the version is re-evaluated under its real source.
func internVersions(ctx context.Context, tx pgx.Tx, set inventory.Set) (all, inserted, reset []int64, err error) {
	n := len(set.Items)
	if n == 0 {
		return nil, nil, nil, nil
	}
	names := make([]string, n)
	versions := make([]string, n)
	arches := make([]string, n)
	sources := make([]string, n)
	sourceVersions := make([]string, n)
	inferred := make([]bool, n)
	for i, it := range set.Items {
		names[i], versions[i], arches[i] = it.Name, it.Version, it.Arch
		sources[i], sourceVersions[i], inferred[i] = it.Source, it.SourceVersion, it.SourceInferred
	}

	// ORDER BY gives every transaction the same row-lock order on
	// software_versions, so two hosts interning overlapping sets can't
	// deadlock. xmax = 0 distinguishes a fresh insert from an update.
	rows, err := tx.Query(ctx, `
		INSERT INTO software_versions
			(ecosystem, distro, release, name, version, arch, source_name, source_version, source_inferred)
		SELECT $1, $2, $3, t.name, t.version, t.arch, t.src, t.srcv, t.inf
		FROM unnest($4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::bool[])
			AS t(name, version, arch, src, srcv, inf)
		ORDER BY t.name, t.version, t.arch
		ON CONFLICT (ecosystem, distro, release, name, version, arch) DO UPDATE SET
			source_name     = EXCLUDED.source_name,
			source_version  = EXCLUDED.source_version,
			source_inferred = false,
			matcher_version = NULL,
			evaluated_at    = NULL
		WHERE software_versions.source_inferred AND NOT EXCLUDED.source_inferred
		RETURNING id, (xmax = 0) AS inserted
	`, set.Ecosystem, set.Distro, set.Release, names, versions, arches, sources, sourceVersions, inferred)
	if err != nil {
		return nil, nil, nil, err
	}
	for rows.Next() {
		var id int64
		var isNew bool
		if err := rows.Scan(&id, &isNew); err != nil {
			rows.Close()
			return nil, nil, nil, err
		}
		if isNew {
			inserted = append(inserted, id)
		} else {
			reset = append(reset, id) // only rows the DO UPDATE's WHERE let through are returned
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, err
	}

	rows, err = tx.Query(ctx, `
		SELECT sv.id
		FROM unnest($4::text[], $5::text[], $6::text[]) AS t(name, version, arch)
		JOIN software_versions sv
		  ON sv.ecosystem = $1 AND sv.distro = $2 AND sv.release = $3
		 AND sv.name = t.name AND sv.version = t.version AND sv.arch = t.arch
	`, set.Ecosystem, set.Distro, set.Release, names, versions, arches)
	if err != nil {
		return nil, nil, nil, err
	}
	all, err = pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return nil, nil, nil, err
	}
	if len(all) != n {
		return nil, nil, nil, errors.New("intern: resolved id count does not match set size")
	}
	return all, inserted, reset, nil
}
