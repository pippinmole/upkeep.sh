package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
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
	Updated int // open ranges whose live columns were updated in place
}

// applyFactSet reconciles one range table (host_services, host_listeners,
// host_users, host_containers, host_images) with one authoritative set,
// the way applyInventory does for packages. Must run inside the snapshot
// transaction, after the host row is locked.
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
//   - a Partial row never overwrites its open range's Detail columns
//     (reconcileRanges)
func applyFactSet(ctx context.Context, tx pgx.Tx, hostID, snapshotID string, at time.Time, set hostfacts.Set) (FactResult, error) {
	res := FactResult{Kind: set.Kind}

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

	owner := rangeOwner{cols: []string{"host_id"}, vals: []any{hostID}}
	if res.Opened, res.Closed, res.Updated, err = reconcileRanges(ctx, tx, owner, snapshotID, at, set); err != nil {
		return res, err
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
	`, hostID, set.Kind, hash, at, snapshotID, res.Opened+res.Closed > 0)
	return res, err
}

// rangeOwner names the columns a range table's rows belong to: host_id
// for the host tables, (workspace_id, cluster_id) for swarm_services.
type rangeOwner struct {
	cols []string
	vals []any
}

// where returns "c1 = $1 AND c2 = $2 ..." for the owner columns.
func (o rangeOwner) where(alias string) string {
	parts := make([]string, len(o.cols))
	for i, c := range o.cols {
		parts[i] = fmt.Sprintf("%s%s = $%d", alias, c, i+1)
	}
	return strings.Join(parts, " AND ")
}

// reconcileRanges diffs one set against the owner's open ranges in the
// set's table and applies the result at boundary at: closes changed and
// (unless Additive) missing keys, opens new and changed ones, and updates
// Live columns of ranges that stay open. The caller does the per-kind
// bookkeeping (stale / unchanged checks, set hash).
//
// Partial rows (tables with Detail columns): a partial row takes the open
// range's detail_hash, so it compares equal to that range when only the
// detail is unknown. When it still opens a new range (a hashed list field
// changed, e.g. the state), the new range copies the Detail columns, and
// every Live column the partial row doesn't know (nil), from the range it
// replaces. Without an open range its Detail columns are NULL (unknown).
//
// Table and column names come from hostfacts' fixed Table values, never
// from input, so interpolating them is safe.
func reconcileRanges(ctx context.Context, tx pgx.Tx, owner rangeOwner, snapshotID string, at time.Time, set hostfacts.Set) (opened, closed, updated int, err error) {
	t := set.Table
	hasDetail, hasLive := len(t.Detail) > 0, len(t.Live) > 0
	n := len(owner.vals)

	args := append([]any{}, owner.vals...)
	where := owner.where("")
	if t.ScopeCol != "" {
		where += fmt.Sprintf(" AND %s = $%d", t.ScopeCol, n+1)
		args = append(args, set.Scope)
	}
	sel := "row_key, row_hash"
	if hasDetail {
		sel += ", detail_hash"
	}
	if hasLive {
		sel += ", live_hash"
	}
	rows, err := tx.Query(ctx, fmt.Sprintf(`SELECT %s FROM %s WHERE %s AND removed_at IS NULL`, sel, t.Name, where), args...)
	if err != nil {
		return 0, 0, 0, err
	}
	open := map[string]hostfacts.Open{}
	for rows.Next() {
		var k string
		var o hostfacts.Open
		dest := []any{&k, &o.Hash}
		if hasDetail {
			dest = append(dest, &o.DetailHash)
		}
		if hasLive {
			dest = append(dest, &o.LiveHash)
		}
		if err := rows.Scan(dest...); err != nil {
			rows.Close()
			return 0, 0, 0, err
		}
		open[k] = o
	}
	if err := rows.Err(); err != nil {
		return 0, 0, 0, err
	}

	if hasDetail {
		set.Rows = slices.Clone(set.Rows) // don't rewrite the caller's rows
		for i, r := range set.Rows {
			if o, ok := open[r.Key]; ok && r.Partial {
				set.Rows[i] = hostfacts.WithDetailHash(t, r, o.DetailHash)
			}
		}
	}
	add, closeKeys, live := hostfacts.DiffRanges(open, set)

	if len(closeKeys) > 0 {
		if _, err := tx.Exec(ctx, fmt.Sprintf(`
			UPDATE %s SET removed_at = $%d, removed_snapshot_id = $%d
			WHERE %s AND removed_at IS NULL AND row_key = ANY($%d::text[])`, t.Name, n+2, n+3, owner.where(""), n+1),
			append(append([]any{}, owner.vals...), closeKeys, at, snapshotID)...); err != nil {
			return 0, 0, 0, fmt.Errorf("close %s ranges: %w", t.Name, err)
		}
	}

	if len(add) > 0 {
		cols := append(append([]string{}, owner.cols...), "row_key", "row_hash", "first_seen_at", "first_seen_snapshot_id")
		cols = append(cols, t.Columns...)
		if hasDetail {
			cols = append(append(cols, t.Detail...), "detail_hash")
		}
		if hasLive {
			cols = append(append(cols, t.Live...), "live_hash")
		}
		data := make([][]any, len(add))
		for i, r := range add {
			if len(r.Values) != len(t.Columns) || (hasLive && len(r.Live) != len(t.Live)) ||
				(hasDetail && !r.Partial && len(r.Detail) != len(t.Detail)) {
				return 0, 0, 0, fmt.Errorf("%s row %q: value count does not match the table", t.Name, r.Key)
			}
			row := append(append([]any{}, owner.vals...), r.Key, r.Hash, at, snapshotID)
			row = append(row, r.Values...)
			if hasDetail {
				if r.Partial {
					row = append(row, make([]any, len(t.Detail))...)
				} else {
					row = append(row, r.Detail...)
				}
				row = append(row, r.DetailHash)
			}
			if hasLive {
				row = append(append(row, r.Live...), r.LiveHash)
			}
			data[i] = row
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{t.Name}, cols, pgx.CopyFromRows(data)); err != nil {
			return 0, 0, 0, fmt.Errorf("open %s ranges: %w", t.Name, err)
		}
	}

	// Partial rows that replaced an open range inherit what they don't
	// know from it (the replaced range was closed at exactly `at`).
	batch := &pgx.Batch{}
	for _, r := range add {
		if _, had := open[r.Key]; !had || !r.Partial {
			continue
		}
		var sets []string
		for _, c := range t.Detail {
			sets = append(sets, fmt.Sprintf("%s = o.%s", c, c))
		}
		for i, c := range t.Live {
			if r.Live[i] == nil {
				sets = append(sets, fmt.Sprintf("%s = o.%s", c, c))
			}
		}
		if len(sets) == 0 {
			continue
		}
		batch.Queue(fmt.Sprintf(`
			UPDATE %[1]s AS c SET %[2]s FROM %[1]s AS o
			WHERE %[3]s AND c.row_key = $%[5]d AND c.removed_at IS NULL
			  AND %[4]s AND o.row_key = $%[5]d AND o.removed_at = $%[6]d`,
			t.Name, strings.Join(sets, ", "), owner.where("c."), owner.where("o."), n+1, n+2),
			append(append([]any{}, owner.vals...), r.Key, at)...)
	}
	// Live columns of ranges that stay open. On a partial row, unknown
	// (nil) live values keep the stored ones.
	for _, r := range live {
		sets := []string{fmt.Sprintf("live_hash = $%d", n+2)}
		qargs := append(append([]any{}, owner.vals...), r.Key, r.LiveHash)
		for i, c := range t.Live {
			if r.Partial && r.Live[i] == nil {
				continue
			}
			qargs = append(qargs, r.Live[i])
			sets = append(sets, fmt.Sprintf("%s = $%d", c, len(qargs)))
		}
		batch.Queue(fmt.Sprintf(`UPDATE %s SET %s WHERE %s AND row_key = $%d AND removed_at IS NULL`,
			t.Name, strings.Join(sets, ", "), owner.where(""), n+1), qargs...)
	}
	if batch.Len() > 0 {
		if err := tx.SendBatch(ctx, batch).Close(); err != nil {
			return 0, 0, 0, fmt.Errorf("update %s ranges: %w", t.Name, err)
		}
	}
	return len(add), len(closeKeys), len(live), nil
}
