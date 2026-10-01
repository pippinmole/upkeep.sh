package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/findings"
)

// ErrUnevaluated is returned by ReconcileHostFindings when the host
// currently has package versions the matcher has not evaluated yet (their
// match job is queued). Reconciling now would resolve findings only to
// reopen them moments later, so the caller retries shortly instead.
var ErrUnevaluated = errors.New("host has package versions not yet evaluated by the matcher")

// ReconcileResult reports one host's findings reconciliation.
type ReconcileResult struct {
	HostFound                        bool
	RunningKernel                    string // "" = unknown
	Images                           int    // images in the vulnerable_image scope with a package list
	Opened, Reopened, Kept, Resolved int
}

// Changed reports whether any finding opened, reopened or resolved (the
// host's vulnerability alert rules need evaluating).
func (r ReconcileResult) Changed() bool { return r.Opened+r.Reopened+r.Resolved > 0 }

// AfterReconcile runs inside the reconcile transaction after findings are
// written (the worker uses it to InsertTx the host's alert rule
// evaluation). An error rolls the reconcile back.
type AfterReconcile func(ctx context.Context, tx pgx.Tx, res ReconcileResult) error

// ReconcileHostFindings makes the host's vulnerable_package findings match
// its current inventory's matches (findings.Build) and its
// vulnerable_image findings match the package lists of the images its
// containers use (findings.BuildImage, imagefindings.go), with one
// findings.Reconcile over both, in one transaction, holding the host row
// lock (the same lock snapshot ingest takes), so it always sees a complete
// inventory.
func (s *Store) ReconcileHostFindings(ctx context.Context, hostID string) (ReconcileResult, error) {
	return s.ReconcileHostFindingsTx(ctx, hostID, nil)
}

// ReconcileHostFindingsTx is ReconcileHostFindings with a hook run in its
// transaction.
func (s *Store) ReconcileHostFindingsTx(ctx context.Context, hostID string, after AfterReconcile) (ReconcileResult, error) {
	var res ReconcileResult
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var workspaceID string
	err = tx.QueryRow(ctx, `SELECT workspace_id FROM hosts WHERE id = $1 FOR NO KEY UPDATE`, hostID).Scan(&workspaceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return res, nil // host deleted since the job was queued
	}
	if err != nil {
		return res, err
	}
	res.HostFound = true

	// Images in the vulnerable_image scope, with the owner's effective
	// package list (imagefindings.go).
	images, err := loadHostImages(ctx, tx, hostID, workspaceID)
	if err != nil {
		return res, err
	}
	res.Images = len(images)
	sbomIDs := sbomIDsOf(images)

	var pending bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM host_software hs
			JOIN software_versions sv ON sv.id = hs.software_id
			WHERE hs.host_id = $1 AND hs.removed_at IS NULL AND sv.matcher_version IS NULL)
	`, hostID).Scan(&pending); err != nil {
		return res, err
	}
	if !pending {
		if pending, err = imageListsPending(ctx, tx, sbomIDs); err != nil {
			return res, err
		}
	}
	if pending {
		return res, ErrUnevaluated
	}

	var kernel *string
	err = tx.QueryRow(ctx, `
		SELECT kernel_release FROM snapshots WHERE host_id = $1
		ORDER BY collected_at DESC, received_at DESC LIMIT 1
	`, hostID).Scan(&kernel)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return res, err
	}
	res.RunningKernel = deref(kernel)

	rows, err := tx.Query(ctx, `
		SELECT sv.id, sv.ecosystem, sv.name, sv.match_source, sv.match_version, COALESCE(sv.kernel_release, ''),
		       sw.vuln_key, sw.advisory_ids, sw.fixed_version, COALESCE(sw.fix_channel, ''),
		       COALESCE(sw.fix_advisory_id, ''), sw.distro_severity
		FROM host_software hs
		JOIN software_versions sv ON sv.id = hs.software_id
		JOIN software_vulnerabilities sw ON sw.software_id = sv.id
		WHERE hs.host_id = $1 AND hs.removed_at IS NULL AND sv.match_source IS NOT NULL
	`, hostID)
	if err != nil {
		return res, err
	}
	var matches []findings.HostMatch
	vulnKeys := map[string]bool{}
	for rows.Next() {
		var m findings.HostMatch
		if err := rows.Scan(&m.SoftwareID, &m.Ecosystem, &m.Package, &m.Source, &m.Version, &m.KernelRelease,
			&m.Match.VulnKey, &m.Match.AdvisoryIDs, &m.Match.FixedVersion, &m.Match.FixChannel,
			&m.Match.FixAdvisoryID, &m.Match.Severity); err != nil {
			rows.Close()
			return res, err
		}
		matches = append(matches, m)
		vulnKeys[m.Match.VulnKey] = true
	}
	if err := rows.Err(); err != nil {
		return res, err
	}
	imageMatches, err := loadListMatches(ctx, tx, sbomIDs, vulnKeys)
	if err != nil {
		return res, err
	}

	cves, err := loadCVEs(ctx, tx, vulnKeys)
	if err != nil {
		return res, err
	}
	desired := findings.Build(matches, res.RunningKernel, cves)
	desired = append(desired, buildImageFindings(images, imageMatches, cves)...)

	rows, err = tx.Query(ctx, `
		SELECT id::text, dedup_key, status, first_seen_at, reopened_at, reopen_count
		FROM findings WHERE host_id = $1 AND kind = ANY($2)
	`, hostID, findings.VulnKinds)
	if err != nil {
		return res, err
	}
	existing, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (findings.Existing, error) {
		var e findings.Existing
		err := r.Scan(&e.ID, &e.DedupKey, &e.Status, &e.FirstSeenAt, &e.ReopenedAt, &e.ReopenCount)
		return e, err
	})
	if err != nil {
		return res, err
	}

	now := time.Now().UTC()
	plan := findings.Reconcile(existing, desired, now)
	res.Opened, res.Reopened, res.Kept, res.Resolved = plan.Counts()

	if err := writeFindings(ctx, tx, hostID, plan, now); err != nil {
		return res, err
	}
	if after != nil {
		if err := after(ctx, tx, res); err != nil {
			return res, err
		}
	}
	return res, tx.Commit(ctx)
}

func loadCVEs(ctx context.Context, tx pgx.Tx, keys map[string]bool) (map[string]findings.CVE, error) {
	ids := make([]string, 0, len(keys))
	for k := range keys {
		if strings.HasPrefix(k, "CVE-") {
			ids = append(ids, k)
		}
	}
	out := map[string]findings.CVE{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT id, is_kev, epss_score::float8, epss_percentile::float8, cvss_v3_score::float8
		FROM cves WHERE id = ANY($1)
	`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var c findings.CVE
		if err := rows.Scan(&id, &c.KEV, &c.EPSS, &c.EPSSPercentile, &c.CVSS); err != nil {
			return nil, err
		}
		out[id] = c
	}
	return out, rows.Err()
}

var findingCols = []string{
	"kind", "dedup_key", "vuln_key", "source_package", "installed_version",
	"fixed_version", "fix_channel", "requires_pro", "fix_advisory_id", "advisory_ids",
	"distro_severity", "severity", "severity_rank", "severity_key", "is_kev", "epss_score",
	"epss_percentile", "cvss_v3_score", "software_ids", "packages", "kernel_release",
	"running_kernel_unknown", "first_seen_at", "reopened_at", "reopen_count",
	"image_id", "image_os", "image_arch", "image_variant", "image_refs", "container_names",
}

func writeFindings(ctx context.Context, tx pgx.Tx, hostID string, plan findings.Plan, now time.Time) error {
	if len(plan.Upserts) > 0 {
		if _, err := tx.Exec(ctx, `
			CREATE TEMP TABLE findings_stage (
				kind text, dedup_key text, vuln_key text, source_package text, installed_version text,
				fixed_version text, fix_channel text, requires_pro boolean, fix_advisory_id text,
				advisory_ids text[], distro_severity text, severity text, severity_rank int,
				severity_key bigint, is_kev boolean, epss_score float8, epss_percentile float8,
				cvss_v3_score float8, software_ids bigint[], packages text[], kernel_release text,
				running_kernel_unknown boolean, first_seen_at timestamptz, reopened_at timestamptz,
				reopen_count int, image_id text, image_os text, image_arch text, image_variant text,
				image_refs text[], container_names text[]
			) ON COMMIT DROP
		`); err != nil {
			return err
		}
		stage := make([][]any, len(plan.Upserts))
		for i, u := range plan.Upserts {
			var (
				imgID, imgOS, imgArch, imgVariant any
				refs, containers                  = []string{}, []string{}
			)
			if im := u.Image; im != nil {
				imgID, imgOS, imgArch, imgVariant = im.ID, im.OS, im.Arch, im.Variant
				refs, containers = orEmpty(im.Refs), orEmpty(im.Containers)
			}
			stage[i] = []any{
				u.Kind, u.DedupKey, u.VulnKey, u.Source, u.InstalledVersion,
				u.FixedVersion, nilIfEmpty(u.FixChannel), u.RequiresPro(), nilIfEmpty(u.FixAdvisoryID),
				u.AdvisoryIDs, u.DistroSeverity, u.Severity.Bucket.String(), int(u.Severity.Bucket),
				int64(u.Severity.Key), u.CVE.KEV, u.CVE.EPSS, u.CVE.EPSSPercentile, u.CVE.CVSS,
				u.SoftwareIDs, u.Packages, nilIfEmpty(u.KernelRelease), u.RunningKernelUnknown,
				u.FirstSeenAt, u.ReopenedAt, u.ReopenCount,
				imgID, imgOS, imgArch, imgVariant, refs, containers,
			}
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"findings_stage"}, findingCols, pgx.CopyFromRows(stage)); err != nil {
			return fmt.Errorf("stage findings: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO findings (host_id, status, last_seen_at, resolved_at, details, `+strings.Join(findingCols, ", ")+`)
			SELECT $1, 'open', $2, NULL, '{}', `+strings.Join(findingCols, ", ")+`
			FROM findings_stage
			ON CONFLICT (host_id, dedup_key) DO UPDATE SET
				kind = EXCLUDED.kind, status = 'open', last_seen_at = EXCLUDED.last_seen_at,
				resolved_at = NULL, vuln_key = EXCLUDED.vuln_key,
				source_package = EXCLUDED.source_package, installed_version = EXCLUDED.installed_version,
				fixed_version = EXCLUDED.fixed_version, fix_channel = EXCLUDED.fix_channel,
				requires_pro = EXCLUDED.requires_pro, fix_advisory_id = EXCLUDED.fix_advisory_id,
				advisory_ids = EXCLUDED.advisory_ids, distro_severity = EXCLUDED.distro_severity,
				severity = EXCLUDED.severity, severity_rank = EXCLUDED.severity_rank,
				severity_key = EXCLUDED.severity_key, is_kev = EXCLUDED.is_kev,
				epss_score = EXCLUDED.epss_score, epss_percentile = EXCLUDED.epss_percentile,
				cvss_v3_score = EXCLUDED.cvss_v3_score, software_ids = EXCLUDED.software_ids,
				packages = EXCLUDED.packages, kernel_release = EXCLUDED.kernel_release,
				running_kernel_unknown = EXCLUDED.running_kernel_unknown,
				first_seen_at = EXCLUDED.first_seen_at, reopened_at = EXCLUDED.reopened_at,
				reopen_count = EXCLUDED.reopen_count,
				image_id = EXCLUDED.image_id, image_os = EXCLUDED.image_os,
				image_arch = EXCLUDED.image_arch, image_variant = EXCLUDED.image_variant,
				image_refs = EXCLUDED.image_refs, container_names = EXCLUDED.container_names
		`, hostID, now); err != nil {
			return fmt.Errorf("upsert findings: %w", err)
		}
	}
	if len(plan.Resolve) > 0 {
		if _, err := tx.Exec(ctx, `
			UPDATE findings SET status = 'resolved', resolved_at = $2
			WHERE id = ANY($1::uuid[]) AND status = 'open'
		`, plan.Resolve, now); err != nil {
			return err
		}
	}
	return nil
}

// RerankResult reports a severity re-rank.
type RerankResult struct {
	Checked, Updated int
}

// RerankFindings recomputes severity for open findings (both kinds)
// whose CVE's enrichment (KEV, EPSS, CVSS) changed at or after since
// (cves.updated_at), and updates the ones whose ranking inputs or result
// changed. It never changes the open/resolved lifecycle. A zero since
// re-ranks every open finding.
func (s *Store) RerankFindings(ctx context.Context, since time.Time) (RerankResult, error) {
	var res RerankResult
	var after string
	for {
		rows, err := s.Pool.Query(ctx, `
			SELECT f.id::text, f.distro_severity, COALESCE(f.fix_channel, ''), f.severity_key,
			       f.is_kev, f.epss_score::float8, f.epss_percentile::float8, f.cvss_v3_score::float8,
			       c.is_kev, c.epss_score::float8, c.epss_percentile::float8, c.cvss_v3_score::float8
			FROM findings f
			JOIN cves c ON c.id = f.vuln_key
			WHERE f.status = 'open' AND f.kind = ANY($1) AND c.updated_at >= $2 AND f.id::text > $3
			ORDER BY f.id::text LIMIT 5000
		`, findings.VulnKinds, since, after)
		if err != nil {
			return res, err
		}
		var (
			ids, buckets     []string
			ranks            []int
			keys             []int64
			kevs             []bool
			epss, pcts, cvss []*float64
			n                int
		)
		for rows.Next() {
			var (
				id, fixChannel   string
				dsev             *string
				oldKey           int64
				oldKEV           bool
				oldE, oldP, oldC *float64
				c                findings.CVE
			)
			if err := rows.Scan(&id, &dsev, &fixChannel, &oldKey, &oldKEV, &oldE, &oldP, &oldC,
				&c.KEV, &c.EPSS, &c.EPSSPercentile, &c.CVSS); err != nil {
				rows.Close()
				return res, err
			}
			n++
			after = id
			r := findings.Assess(dsev, fixChannel, c)
			if int64(r.Key) == oldKey && oldKEV == c.KEV && eqF(oldE, c.EPSS) && eqF(oldP, c.EPSSPercentile) && eqF(oldC, c.CVSS) {
				continue
			}
			ids, buckets, ranks, keys = append(ids, id), append(buckets, r.Bucket.String()), append(ranks, int(r.Bucket)), append(keys, int64(r.Key))
			kevs, epss, pcts, cvss = append(kevs, c.KEV), append(epss, c.EPSS), append(pcts, c.EPSSPercentile), append(cvss, c.CVSS)
		}
		if err := rows.Err(); err != nil {
			return res, err
		}
		res.Checked += n
		if len(ids) > 0 {
			tag, err := s.Pool.Exec(ctx, `
				UPDATE findings f SET severity = u.bucket, severity_rank = u.rank, severity_key = u.key,
					is_kev = u.kev, epss_score = u.epss, epss_percentile = u.pct, cvss_v3_score = u.cvss
				FROM unnest($1::uuid[], $2::text[], $3::int[], $4::bigint[], $5::bool[],
				            $6::float8[], $7::float8[], $8::float8[]) AS u(id, bucket, rank, key, kev, epss, pct, cvss)
				WHERE f.id = u.id AND f.status = 'open'
			`, ids, buckets, ranks, keys, kevs, epss, pcts, cvss)
			if err != nil {
				return res, err
			}
			res.Updated += int(tag.RowsAffected())
		}
		if n < 5000 {
			return res, nil
		}
	}
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func eqF(a, b *float64) bool {
	if a == nil || b == nil {
		return a == b
	}
	// Stored as numeric(6,5)/(3,1): compare at that precision.
	d := *a - *b
	return d < 1e-6 && d > -1e-6
}
