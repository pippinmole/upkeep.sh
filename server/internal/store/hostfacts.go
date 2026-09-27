package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/hostfacts"
)

// FactResult says what applyFactSet did for one kind. Outcomes are the
// same as for package inventory.
type FactResult struct {
	Kind    string
	Outcome InventoryOutcome
	Opened  int // ranges opened
	Closed  int // ranges closed
}

// applyFactSet reconciles one range table (host_services, host_listeners,
// host_users) with one authoritative set, the way applyInventory does for
// packages. Must run inside the snapshot transaction, after the host row
// is locked.
//
// Invariants maintained:
//   - at most one open range per (host, row_key) (unique partial index);
//     a key whose values changed has its range closed and a new one opened
//     at the same boundary
//   - only rows in the set's scope (e.g. transport = 'udp') are read or
//     written, so kinds owned by different collectors never interfere
//   - boundaries strictly increase per (host, kind): a push not newer than
//     host_fact_state.confirmed_at is stale and ignored
//   - an Additive (truncated) set never closes a key it doesn't mention,
//     and leaves set_hash NULL so the next full push diffs
func applyFactSet(ctx context.Context, tx pgx.Tx, hostID, snapshotID string, at time.Time, set hostfacts.Set) (FactResult, error) {
	res := FactResult{Kind: set.Kind}
	t := set.Table

	var (
		curHash     *string
		confirmedAt time.Time
		haveState   = true
	)
	err := tx.QueryRow(ctx, `
		SELECT set_hash, confirmed_at FROM host_fact_state WHERE host_id = $1 AND kind = $2
	`, hostID, set.Kind).Scan(&curHash, &confirmedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		haveState = false
	} else if err != nil {
		return res, err
	}
	if haveState && !at.After(confirmedAt) {
		res.Outcome = InventoryStale
		return res, nil
	}
	if haveState && !set.Additive && curHash != nil && *curHash == set.Hash {
		res.Outcome = InventoryUnchanged
		_, err := tx.Exec(ctx, `
			UPDATE host_fact_state SET confirmed_at = $3, confirmed_snapshot_id = $4
			WHERE host_id = $1 AND kind = $2
		`, hostID, set.Kind, at, snapshotID)
		return res, err
	}
	res.Outcome = InventoryDiffed

	// Table and column names come from hostfacts' fixed Table values,
	// never from input, so interpolating them is safe.
	scopeWhere, args := "", []any{hostID}
	if t.ScopeCol != "" {
		scopeWhere = fmt.Sprintf(" AND %s = $2", t.ScopeCol)
		args = append(args, set.Scope)
	}
	rows, err := tx.Query(ctx, fmt.Sprintf(
		`SELECT row_key, row_hash FROM %s WHERE host_id = $1 AND removed_at IS NULL%s`, t.Name, scopeWhere), args...)
	if err != nil {
		return res, err
	}
	open := map[string]string{}
	for rows.Next() {
		var k, h string
		if err := rows.Scan(&k, &h); err != nil {
			rows.Close()
			return res, err
		}
		open[k] = h
	}
	if err := rows.Err(); err != nil {
		return res, err
	}

	add, closeKeys := hostfacts.Diff(open, set)
	res.Opened, res.Closed = len(add), len(closeKeys)

	if len(closeKeys) > 0 {
		if _, err := tx.Exec(ctx, fmt.Sprintf(`
			UPDATE %s SET removed_at = $3, removed_snapshot_id = $4
			WHERE host_id = $1 AND removed_at IS NULL AND row_key = ANY($2::text[])`, t.Name),
			hostID, closeKeys, at, snapshotID); err != nil {
			return res, fmt.Errorf("close %s ranges: %w", t.Name, err)
		}
	}
	if len(add) > 0 {
		cols := append([]string{"host_id", "row_key", "row_hash", "first_seen_at", "first_seen_snapshot_id"}, t.Columns...)
		data := make([][]any, len(add))
		for i, r := range add {
			if len(r.Values) != len(t.Columns) {
				return res, fmt.Errorf("%s row %q: %d values for %d columns", t.Name, r.Key, len(r.Values), len(t.Columns))
			}
			data[i] = append([]any{hostID, r.Key, r.Hash, at, snapshotID}, r.Values...)
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{t.Name}, cols, pgx.CopyFromRows(data)); err != nil {
			return res, fmt.Errorf("open %s ranges: %w", t.Name, err)
		}
	}

	var hash any = set.Hash
	if set.Additive {
		hash = nil
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO host_fact_state (host_id, kind, set_hash, confirmed_at, confirmed_snapshot_id, changed_at)
		VALUES ($1, $2, $3, $4, $5, $4)
		ON CONFLICT (host_id, kind) DO UPDATE SET
			set_hash              = EXCLUDED.set_hash,
			confirmed_at          = EXCLUDED.confirmed_at,
			confirmed_snapshot_id = EXCLUDED.confirmed_snapshot_id,
			changed_at = CASE WHEN $6 THEN EXCLUDED.changed_at ELSE host_fact_state.changed_at END
	`, hostID, set.Kind, hash, at, snapshotID, len(add)+len(closeKeys) > 0)
	return res, err
}
