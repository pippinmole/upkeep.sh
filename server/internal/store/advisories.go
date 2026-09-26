package store

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/cvss"
	"github.com/pippinmole/upkeep.sh/server/internal/osv"
)

// DistroReleases returns every distro_releases row (supported or not).
func (s *Store) DistroReleases(ctx context.Context) ([]osv.Release, error) {
	rows, err := s.Pool.Query(ctx, `SELECT distro, codename, version, supported FROM distro_releases`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (osv.Release, error) {
		var rel osv.Release
		err := r.Scan(&rel.Distro, &rel.Codename, &rel.Version, &rel.Supported)
		return rel, err
	})
}

// AdvisoryWriteResult counts what UpsertAdvisories did.
type AdvisoryWriteResult struct {
	Written   int // inserted or updated advisories
	Unchanged int // same content_hash as stored: skipped
	Rows      int // advisory_affected rows written
	Dirty     int // (distro, release, source package) keys marked in advisory_changes
}

func (r *AdvisoryWriteResult) Add(o AdvisoryWriteResult) {
	r.Written += o.Written
	r.Unchanged += o.Unchanged
	r.Rows += o.Rows
	r.Dirty += o.Dirty
}

// UpsertAdvisories writes a batch of normalized advisories in one
// transaction. Advisories whose content_hash matches the stored one are
// skipped. For the rest the advisory row is upserted and its
// advisory_affected rows replaced; every (distro, release, source package)
// whose rows differ between old and new is recorded in advisory_changes
// in the same transaction, so the matcher can never miss a change. CVSS
// vectors from per-CVE records are upserted into cves.
func (s *Store) UpsertAdvisories(ctx context.Context, advs []osv.Advisory) (AdvisoryWriteResult, error) {
	var res AdvisoryWriteResult
	if len(advs) == 0 {
		return res, nil
	}
	byID := make(map[string]*osv.Advisory, len(advs))
	ids := make([]string, 0, len(advs))
	for i := range advs {
		if _, dup := byID[advs[i].ID]; !dup {
			ids = append(ids, advs[i].ID)
		}
		byID[advs[i].ID] = &advs[i]
	}

	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `SELECT id, content_hash FROM advisories WHERE id = ANY($1)`, ids)
	if err != nil {
		return res, err
	}
	stored := map[string]string{}
	for rows.Next() {
		var id, h string
		if err := rows.Scan(&id, &h); err != nil {
			rows.Close()
			return res, err
		}
		stored[id] = h
	}
	if err := rows.Err(); err != nil {
		return res, err
	}

	var changed []string
	for _, id := range ids {
		if h, ok := stored[id]; ok && h == byID[id].ContentHash {
			res.Unchanged++
			continue
		}
		changed = append(changed, id)
	}
	if len(changed) == 0 {
		return res, tx.Commit(ctx)
	}

	old, err := loadAffected(ctx, tx, changed)
	if err != nil {
		return res, err
	}

	batch := &pgx.Batch{}
	for _, id := range changed {
		a := byID[id]
		batch.Queue(`
			INSERT INTO advisories
				(id, source, vuln_key, cve_ids, aliases, upstream, related, summary, details, severity,
				 published_at, modified_at, withdrawn_at, raw, content_hash, synced_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), NULLIF($9, ''), $10, $11, $12, $13, $14, $15, now())
			ON CONFLICT (id) DO UPDATE SET
				source = EXCLUDED.source, vuln_key = EXCLUDED.vuln_key, cve_ids = EXCLUDED.cve_ids,
				aliases = EXCLUDED.aliases, upstream = EXCLUDED.upstream, related = EXCLUDED.related,
				summary = EXCLUDED.summary, details = EXCLUDED.details, severity = EXCLUDED.severity,
				published_at = EXCLUDED.published_at, modified_at = EXCLUDED.modified_at,
				withdrawn_at = EXCLUDED.withdrawn_at, raw = EXCLUDED.raw,
				content_hash = EXCLUDED.content_hash, synced_at = now()
		`, a.ID, a.Source, a.VulnKey, a.CVEIDs, a.Aliases, a.Upstream, a.Related, a.Summary, a.Details,
			a.Severity, a.Published, a.Modified, a.Withdrawn, string(a.Raw), a.ContentHash)
	}
	if err := tx.SendBatch(ctx, batch).Close(); err != nil {
		return res, fmt.Errorf("upsert advisories: %w", err)
	}
	res.Written = len(changed)

	if _, err := tx.Exec(ctx, `DELETE FROM advisory_affected WHERE advisory_id = ANY($1)`, changed); err != nil {
		return res, err
	}
	var copyRows [][]any
	dirty := map[osv.Key]bool{}
	for _, id := range changed {
		a := byID[id]
		newSigs := map[osv.Key][]string{}
		for _, r := range a.Affected {
			copyRows = append(copyRows, []any{a.ID, r.Distro, r.Release, r.SourcePackage, r.Channel,
				r.Introduced, r.FixedVersion, r.LastAffected, r.DistroSeverity, r.Status, r.Ecosystem})
			newSigs[r.Key()] = append(newSigs[r.Key()], rowSig(r.Channel, r.Introduced, r.FixedVersion, r.LastAffected, r.DistroSeverity, r.Status))
		}
		for k := range diffKeys(old[id], newSigs) {
			dirty[k] = true
		}
	}
	if len(copyRows) > 0 {
		n, err := tx.CopyFrom(ctx, pgx.Identifier{"advisory_affected"},
			[]string{"advisory_id", "distro", "release", "source_package", "channel",
				"introduced", "fixed_version", "last_affected", "distro_severity", "status", "ecosystem"},
			pgx.CopyFromRows(copyRows))
		if err != nil {
			return res, fmt.Errorf("copy advisory_affected: %w", err)
		}
		res.Rows = int(n)
	}
	if err := markDirty(ctx, tx, dirty); err != nil {
		return res, err
	}
	res.Dirty = len(dirty)

	if err := upsertCVSS(ctx, tx, changed, byID); err != nil {
		return res, err
	}
	return res, tx.Commit(ctx)
}

func rowSig(channel, introduced string, fixed, last, sev *string, status string) string {
	p := func(s *string) string {
		if s == nil {
			return "\x01"
		}
		return *s
	}
	return strings.Join([]string{channel, introduced, p(fixed), p(last), p(sev), status}, "\x00")
}

// diffKeys returns the keys whose row signatures differ between old and new.
func diffKeys(old, new map[osv.Key][]string) map[osv.Key]bool {
	out := map[osv.Key]bool{}
	for k, o := range old {
		n := new[k]
		slices.Sort(o)
		slices.Sort(n)
		if !slices.Equal(o, n) {
			out[k] = true
		}
	}
	for k := range new {
		if _, ok := old[k]; !ok {
			out[k] = true
		}
	}
	return out
}

func loadAffected(ctx context.Context, tx pgx.Tx, ids []string) (map[string]map[osv.Key][]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT advisory_id, distro, release, source_package, channel, introduced,
		       fixed_version, last_affected, distro_severity, status
		FROM advisory_affected WHERE advisory_id = ANY($1)
	`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[osv.Key][]string{}
	for rows.Next() {
		var (
			id, channel, introduced, status string
			k                               osv.Key
			fixed, last, sev                *string
		)
		if err := rows.Scan(&id, &k.Distro, &k.Release, &k.SourcePackage, &channel, &introduced, &fixed, &last, &sev, &status); err != nil {
			return nil, err
		}
		if out[id] == nil {
			out[id] = map[osv.Key][]string{}
		}
		out[id][k] = append(out[id][k], rowSig(channel, introduced, fixed, last, sev, status))
	}
	return out, rows.Err()
}

func markDirty(ctx context.Context, tx pgx.Tx, keys map[osv.Key]bool) error {
	if len(keys) == 0 {
		return nil
	}
	var d, r, p []string
	for k := range keys {
		d, r, p = append(d, k.Distro), append(r, k.Release), append(p, k.SourcePackage)
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO advisory_changes (distro, release, source_package, changed_at)
		SELECT d, r, p, now() FROM unnest($1::text[], $2::text[], $3::text[]) AS t(d, r, p)
		ON CONFLICT (distro, release, source_package) DO UPDATE SET changed_at = now()
	`, d, r, p)
	return err
}

// upsertCVSS records CVSS v3 vectors (and derived base scores) from
// per-CVE records on their cves row, creating it if needed. The most
// recently synced vector wins; description is only filled if empty.
func upsertCVSS(ctx context.Context, tx pgx.Tx, ids []string, byID map[string]*osv.Advisory) error {
	var cveIDs, vectors, descs []string
	var scores []*string
	seen := map[string]bool{}
	for _, id := range ids {
		a := byID[id]
		if a.CVSSv3Vector == "" || !osv.IsCVE(a.VulnKey) || seen[a.VulnKey] {
			continue
		}
		seen[a.VulnKey] = true
		var score *string
		if f, err := cvss.V3BaseScore(a.CVSSv3Vector); err == nil {
			s := fmt.Sprintf("%.1f", f)
			score = &s
		}
		cveIDs = append(cveIDs, a.VulnKey)
		vectors = append(vectors, a.CVSSv3Vector)
		scores = append(scores, score)
		descs = append(descs, a.Details)
	}
	if len(cveIDs) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO cves (id, cvss_v3_vector, cvss_v3_score, description)
		SELECT id, vec, score::numeric, NULLIF(descr, '')
		FROM unnest($1::text[], $2::text[], $3::text[], $4::text[]) AS t(id, vec, score, descr)
		ON CONFLICT (id) DO UPDATE SET
			cvss_v3_vector = EXCLUDED.cvss_v3_vector,
			cvss_v3_score  = EXCLUDED.cvss_v3_score,
			description    = COALESCE(cves.description, EXCLUDED.description),
			updated_at     = now()
		WHERE cves.cvss_v3_vector IS DISTINCT FROM EXCLUDED.cvss_v3_vector
		   OR cves.description IS NULL AND EXCLUDED.description IS NOT NULL
	`, cveIDs, vectors, scores, descs)
	return err
}

// DeleteAdvisories removes the given advisories of a source (incremental
// sync: records withdrawn from OSV, or no longer touching a supported
// release), marking their packages dirty first. Returns how many existed.
func (s *Store) DeleteAdvisories(ctx context.Context, source string, ids []string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	return s.deleteAdvisoriesWhere(ctx, `source = $1 AND id = ANY($2::text[])`, source, ids)
}

// DeleteAdvisoriesExcept removes every advisory of a source whose id is
// not in keep (full sync: the set in all.zip is authoritative).
func (s *Store) DeleteAdvisoriesExcept(ctx context.Context, source string, keep []string) (int, error) {
	return s.deleteAdvisoriesWhere(ctx, `source = $1 AND id NOT IN (SELECT unnest($2::text[]))`, source, keep)
}

func (s *Store) deleteAdvisoriesWhere(ctx context.Context, where string, source string, ids []string) (int, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO advisory_changes (distro, release, source_package, changed_at)
		SELECT DISTINCT aa.distro, aa.release, aa.source_package, now()
		FROM advisory_affected aa
		WHERE aa.advisory_id IN (SELECT id FROM advisories WHERE `+where+`)
		ON CONFLICT (distro, release, source_package) DO UPDATE SET changed_at = now()
	`, source, ids); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM advisories WHERE `+where, source, ids)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), tx.Commit(ctx)
}

// AdvisoryModifiedAt returns the stored modified_at for the given ids of a
// source (missing ids are absent from the map).
func (s *Store) AdvisoryModifiedAt(ctx context.Context, ids []string) (map[string]time.Time, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, modified_at FROM advisories WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var id string
		var t time.Time
		if err := rows.Scan(&id, &t); err != nil {
			return nil, err
		}
		out[id] = t
	}
	return out, rows.Err()
}

// PendingAdvisoryChanges counts advisory_changes rows not yet drained by
// the matcher.
func (s *Store) PendingAdvisoryChanges(ctx context.Context) (int64, error) {
	var n int64
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM advisory_changes`).Scan(&n)
	return n, err
}
