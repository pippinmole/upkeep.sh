package store

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/matcher"
)

// matcherLock serializes every matcher write transaction (across worker
// replicas too) with pg_advisory_xact_lock. Each evaluation reads the
// advisory rows *after* taking it, so two evaluations of one version can
// never commit out of order (an older read overwriting a newer one).
const matcherLock int64 = 0x75706b2d6d617463 // "upk-matc"

// MatchChunkSize bounds the versions evaluated per transaction: each chunk
// holds row locks on its software_versions rows, which ingest diffs of
// hosts carrying those versions wait on.
const MatchChunkSize = 500

// MatchResult reports what MatchVersions did.
type MatchResult struct {
	Evaluated   int
	Changed     []int64 // versions whose match set (or matched source) changed
	Matches     int     // software_vulnerabilities rows now held by the evaluated versions
	BadVersions int     // installed versions or advisory rows that did not parse
}

func (r *MatchResult) add(o MatchResult) {
	r.Evaluated += o.Evaluated
	r.Changed = append(r.Changed, o.Changed...)
	r.Matches += o.Matches
	r.BadVersions += o.BadVersions
}

// MatchVersions evaluates the given software_versions rows against their
// advisories and materializes the result: software_vulnerabilities is
// replaced for every version whose match set changed, and every evaluated
// version gets matcher_version = matcher.Version, evaluated_at = now(),
// match_source/match_version/kernel_release and max_fixed_version.
// Idempotent. Unknown ids are ignored.
func (s *Store) MatchVersions(ctx context.Context, ids []int64) (MatchResult, error) {
	var res MatchResult
	for len(ids) > 0 {
		n := min(len(ids), MatchChunkSize)
		r, err := s.matchChunk(ctx, ids[:n])
		if err != nil {
			return res, err
		}
		res.add(r)
		ids = ids[n:]
	}
	return res, nil
}

type svRow struct {
	id                              int64
	ecosystem, distro, release      string
	name, version                   string
	sourceName, sourceVersion       *string
	inferred                        bool
	oldMatchSource, oldMatchVersion *string
	target                          matcher.Target
}

type sourceKey struct{ distro, release, source string }

// advisoryKey is the advisory_affected key the version's target joins:
// language packages (no distro, no release) are stored under
// (”, ecosystem) (matcher.AdvisoryScope).
func (r *svRow) advisoryKey() sourceKey {
	d, rel := matcher.AdvisoryScope(r.ecosystem, r.distro, r.release)
	return sourceKey{d, rel, r.target.Source}
}

func (s *Store) matchChunk(ctx context.Context, ids []int64) (MatchResult, error) {
	var res MatchResult
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, matcherLock); err != nil {
		return res, err
	}

	// Lock in the same order ingest's internVersions upserts rows
	// (name, version, arch within one distro release), so a matcher chunk
	// and an ingest diff sharing rows cannot deadlock.
	rows, err := tx.Query(ctx, `
		SELECT id, ecosystem, distro, release, name, version, source_name, source_version,
		       source_inferred, match_source, match_version
		FROM software_versions WHERE id = ANY($1)
		ORDER BY name, version, arch, distro, release, ecosystem
		FOR UPDATE
	`, ids)
	if err != nil {
		return res, err
	}
	var svs []*svRow
	for rows.Next() {
		r := &svRow{}
		if err := rows.Scan(&r.id, &r.ecosystem, &r.distro, &r.release, &r.name, &r.version,
			&r.sourceName, &r.sourceVersion, &r.inferred, &r.oldMatchSource, &r.oldMatchVersion); err != nil {
			rows.Close()
			return res, err
		}
		r.target = matcher.Resolve(matcher.Binary{
			Ecosystem: r.ecosystem, Distro: r.distro, Name: r.name, Version: r.version,
			Source: deref(r.sourceName), SourceVersion: deref(r.sourceVersion), SourceInferred: r.inferred,
		})
		svs = append(svs, r)
	}
	if err := rows.Err(); err != nil {
		return res, err
	}
	if len(svs) == 0 {
		return res, tx.Commit(ctx)
	}

	advRows, err := loadAdvisoryRows(ctx, tx, svs)
	if err != nil {
		return res, err
	}
	old, err := loadMatches(ctx, tx, ids)
	if err != nil {
		return res, err
	}

	var (
		changed, unchanged               []int64
		upIDs                            []int64
		upSrc, upVer, upKernel, upMaxFix []*string
		copyRows                         [][]any
	)
	for _, r := range svs {
		var ms []matcher.Match
		// Resolve only sets a source for ecosystems with a comparator.
		c, _ := matcher.ComparatorFor(r.ecosystem)
		if r.target.Source != "" {
			if err := c.Validate(r.target.Version); err != nil {
				res.BadVersions++
			} else {
				var st matcher.Stats
				ms, st = matcher.Evaluate(r.target.Version, c, advRows[r.advisoryKey()])
				res.BadVersions += st.BadVersions
			}
		}
		res.Evaluated++
		res.Matches += len(ms)
		sameTarget := deref(r.oldMatchSource) == r.target.Source && deref(r.oldMatchVersion) == r.target.Version
		if sameTarget && matcher.SameMatches(old[r.id], ms) {
			unchanged = append(unchanged, r.id)
		} else {
			changed = append(changed, r.id)
			for _, m := range ms {
				var fc any
				if m.FixChannel != "" {
					fc = m.FixChannel
				}
				copyRows = append(copyRows, []any{r.id, m.VulnKey, m.AdvisoryIDs, m.FixedVersion, fc,
					nilIfEmpty(m.FixAdvisoryID), m.Severity, matcher.Version})
			}
		}
		upIDs = append(upIDs, r.id)
		upSrc = append(upSrc, strPtrOrNil(r.target.Source))
		upVer = append(upVer, strPtrOrNil(r.target.Version))
		upKernel = append(upKernel, strPtrOrNil(r.target.KernelRelease))
		if len(ms) > 0 {
			upMaxFix = append(upMaxFix, matcher.MaxStandardFix(c, ms))
		} else {
			upMaxFix = append(upMaxFix, nil)
		}
	}

	if len(changed) > 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM software_vulnerabilities WHERE software_id = ANY($1)`, changed); err != nil {
			return res, err
		}
		if len(copyRows) > 0 {
			if _, err := tx.CopyFrom(ctx, pgx.Identifier{"software_vulnerabilities"},
				[]string{"software_id", "vuln_key", "advisory_ids", "fixed_version", "fix_channel",
					"fix_advisory_id", "distro_severity", "matcher_version"},
				pgx.CopyFromRows(copyRows)); err != nil {
				return res, err
			}
		}
	}
	if len(unchanged) > 0 {
		if _, err := tx.Exec(ctx, `
			UPDATE software_vulnerabilities SET matcher_version = $2
			WHERE software_id = ANY($1) AND matcher_version <> $2
		`, unchanged, matcher.Version); err != nil {
			return res, err
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE software_versions sv SET
			match_source = u.src, match_version = u.ver, kernel_release = u.kernel,
			max_fixed_version = u.maxfix, matcher_version = $6, evaluated_at = now()
		FROM unnest($1::bigint[], $2::text[], $3::text[], $4::text[], $5::text[])
			AS u(id, src, ver, kernel, maxfix)
		WHERE sv.id = u.id
	`, upIDs, upSrc, upVer, upKernel, upMaxFix, matcher.Version); err != nil {
		return res, err
	}
	res.Changed = changed
	return res, tx.Commit(ctx)
}

// loadAdvisoryRows loads every advisory_affected row (with its advisory's
// keys) for the (distro, release, source) targets of svs.
func loadAdvisoryRows(ctx context.Context, tx pgx.Tx, svs []*svRow) (map[sourceKey][]matcher.Row, error) {
	seen := map[sourceKey]bool{}
	var ds, rs, ps []string
	for _, r := range svs {
		if r.target.Source == "" {
			continue
		}
		k := r.advisoryKey()
		if !seen[k] {
			seen[k] = true
			ds, rs, ps = append(ds, k.distro), append(rs, k.release), append(ps, k.source)
		}
	}
	out := map[sourceKey][]matcher.Row{}
	if len(ds) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT aa.distro, aa.release, aa.source_package, aa.advisory_id, a.vuln_key, a.cve_ids,
		       aa.channel, aa.introduced, aa.fixed_version, aa.last_affected, aa.distro_severity, aa.status
		FROM unnest($1::text[], $2::text[], $3::text[]) AS k(d, r, p)
		JOIN advisory_affected aa ON aa.distro = k.d AND aa.release = k.r AND aa.source_package = k.p
		JOIN advisories a ON a.id = aa.advisory_id
		WHERE a.withdrawn_at IS NULL
	`, ds, rs, ps)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			k sourceKey
			m matcher.Row
		)
		if err := rows.Scan(&k.distro, &k.release, &k.source, &m.AdvisoryID, &m.VulnKey, &m.CVEIDs,
			&m.Channel, &m.Introduced, &m.Fixed, &m.LastAffected, &m.Severity, &m.Status); err != nil {
			return nil, err
		}
		out[k] = append(out[k], m)
	}
	return out, rows.Err()
}

// loadMatches returns the stored matches per software id, each sorted by
// vuln_key.
func loadMatches(ctx context.Context, q pgx.Tx, ids []int64) (map[int64][]matcher.Match, error) {
	rows, err := q.Query(ctx, `
		SELECT software_id, vuln_key, advisory_ids, fixed_version, fix_channel, fix_advisory_id, distro_severity
		FROM software_vulnerabilities WHERE software_id = ANY($1)
		ORDER BY software_id, vuln_key
	`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]matcher.Match{}
	for rows.Next() {
		var (
			id          int64
			m           matcher.Match
			fc, fixFrom *string
		)
		if err := rows.Scan(&id, &m.VulnKey, &m.AdvisoryIDs, &m.FixedVersion, &fc, &fixFrom, &m.Severity); err != nil {
			return nil, err
		}
		m.FixChannel, m.FixAdvisoryID = deref(fc), deref(fixFrom)
		out[id] = append(out[id], m)
	}
	for _, ms := range out {
		matcher.SortMatches(ms) // Go string order, as Evaluate returns (not the DB collation)
	}
	return out, rows.Err()
}

// SweepResult reports a matcher sweep.
type SweepResult struct {
	MatchResult
	Seconds float64
}

// SweepStaleVersions evaluates every software_versions row that was never
// evaluated or was evaluated by an older matcher.Version, in id order.
// This covers the initial run, a matcher_version bump, and any version
// whose ingest-time match job was lost.
func (s *Store) SweepStaleVersions(ctx context.Context) (SweepResult, error) {
	start := time.Now()
	var res SweepResult
	var after int64
	for {
		rows, err := s.Pool.Query(ctx, `
			SELECT id FROM software_versions
			WHERE id > $1 AND (matcher_version IS NULL OR matcher_version < $2)
			ORDER BY id LIMIT $3
		`, after, matcher.Version, MatchChunkSize)
		if err != nil {
			return res, err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil {
			return res, err
		}
		if len(ids) == 0 {
			break
		}
		r, err := s.MatchVersions(ctx, ids)
		if err != nil {
			return res, err
		}
		res.add(r)
		after = ids[len(ids)-1]
	}
	res.Seconds = time.Since(start).Seconds()
	return res, nil
}

// DrainOptions scopes DrainAdvisoryChanges.
type DrainOptions struct {
	// Distro restricts the drain to one distro. Empty = every distro in
	// distro_releases plus the language ecosystems' keys (distro '')
	// (keys for anything else, e.g. test fixtures, are left alone).
	Distro string
	// BatchSize is the number of keys read per round (default 1000).
	BatchSize int
}

// DrainResult reports an advisory_changes drain.
type DrainResult struct {
	MatchResult
	Keys       int // keys processed (deleted, or re-dirtied meanwhile and kept)
	KeysWithSW int // keys that had at least one matched version
	Kept       int // keys changed again while being processed (left for the next drain)
	Seconds    float64
}

type changeKey struct {
	distro, release, source string
	changedAt               time.Time
}

// DrainAdvisoryChanges is the advisory_rematch protocol: repeatedly read a
// batch of advisory_changes rows (key + changed_at), re-evaluate every
// software_versions row whose match_source is that (distro, release,
// source package), then delete each key only if its changed_at is still
// exactly the value read. Equality (not <=) is deliberate: a sync
// transaction that started before the read but committed after it writes
// its own (earlier) now(), and that key must survive for the next drain.
//
// Versions never evaluated yet have no match_source and are not found
// here; they are evaluated by their own match job or the sweep, which read
// advisories after this drain's key read or after the key is re-dirtied.
func (s *Store) DrainAdvisoryChanges(ctx context.Context, opts DrainOptions) (DrainResult, error) {
	start := time.Now()
	var res DrainResult
	batch := opts.BatchSize
	if batch <= 0 {
		batch = 1000
	}
	var (
		lastAt  time.Time
		lastKey [3]string
	)
	for {
		// Keyset pagination over (changed_at, key): rows kept because they
		// changed again get a newer changed_at and are revisited once.
		rows, err := s.Pool.Query(ctx, `
			SELECT ac.distro, ac.release, ac.source_package, ac.changed_at
			FROM advisory_changes ac
			WHERE ($1 = '' AND (ac.distro = '' -- language ecosystems
			                    OR EXISTS (SELECT 1 FROM distro_releases dr
			                               WHERE dr.distro = ac.distro AND dr.codename = ac.release))
			       OR ac.distro = $1)
			  AND (ac.changed_at, ac.distro, ac.release, ac.source_package) > ($2, $3, $4, $5)
			ORDER BY ac.changed_at, ac.distro, ac.release, ac.source_package
			LIMIT $6
		`, opts.Distro, lastAt, lastKey[0], lastKey[1], lastKey[2], batch)
		if err != nil {
			return res, err
		}
		var keys []changeKey
		for rows.Next() {
			var k changeKey
			if err := rows.Scan(&k.distro, &k.release, &k.source, &k.changedAt); err != nil {
				rows.Close()
				return res, err
			}
			keys = append(keys, k)
		}
		if err := rows.Err(); err != nil {
			return res, err
		}
		if len(keys) == 0 {
			break
		}
		last := keys[len(keys)-1]
		lastAt, lastKey = last.changedAt, [3]string{last.distro, last.release, last.source}

		var ds, rs, ps []string
		var ats []time.Time
		for _, k := range keys {
			ds, rs, ps, ats = append(ds, k.distro), append(rs, k.release), append(ps, k.source), append(ats, k.changedAt)
		}
		rows, err = s.Pool.Query(ctx, `
			SELECT id, d, r, p FROM (
				SELECT sv.id, k.d, k.r, k.p
				FROM unnest($1::text[], $2::text[], $3::text[]) AS k(d, r, p)
				JOIN software_versions sv ON sv.distro = k.d AND sv.release = k.r AND sv.match_source = k.p
				WHERE k.d <> ''
				UNION ALL
				-- language keys are ('', ecosystem, name) (matcher.AdvisoryScope)
				SELECT sv.id, k.d, k.r, k.p
				FROM unnest($1::text[], $2::text[], $3::text[]) AS k(d, r, p)
				JOIN software_versions sv ON sv.distro = '' AND sv.release = '' AND sv.match_source = k.p
				                         AND sv.ecosystem = k.r
				WHERE k.d = ''
			) v
			ORDER BY id
		`, ds, rs, ps)
		if err != nil {
			return res, err
		}
		var ids []int64
		withSW := map[sourceKey]bool{}
		for rows.Next() {
			var id int64
			var k sourceKey
			if err := rows.Scan(&id, &k.distro, &k.release, &k.source); err != nil {
				rows.Close()
				return res, err
			}
			ids = append(ids, id)
			withSW[k] = true
		}
		if err := rows.Err(); err != nil {
			return res, err
		}
		r, err := s.MatchVersions(ctx, ids)
		if err != nil {
			return res, err
		}
		res.add(r)
		res.KeysWithSW += len(withSW)

		tag, err := s.Pool.Exec(ctx, `
			DELETE FROM advisory_changes ac
			USING unnest($1::text[], $2::text[], $3::text[], $4::timestamptz[]) AS k(d, r, p, at)
			WHERE ac.distro = k.d AND ac.release = k.r AND ac.source_package = k.p AND ac.changed_at = k.at
		`, ds, rs, ps, ats)
		if err != nil {
			return res, err
		}
		res.Keys += len(keys)
		res.Kept += len(keys) - int(tag.RowsAffected())
		if len(keys) < batch {
			break
		}
	}
	res.Seconds = time.Since(start).Seconds()
	if res.BadVersions > 0 {
		log.Printf("advisory_rematch: %d unparsable versions skipped", res.BadVersions)
	}
	return res, nil
}

// HostsWithSoftware returns the hosts that currently have any of the given
// versions installed (open host_software ranges).
func (s *Store) HostsWithSoftware(ctx context.Context, ids []int64) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT DISTINCT host_id::text FROM host_software
		WHERE software_id = ANY($1) AND removed_at IS NULL
	`, ids)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func strPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
