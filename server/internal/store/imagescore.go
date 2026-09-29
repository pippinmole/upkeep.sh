package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/findings"
	"github.com/pippinmole/upkeep.sh/server/internal/matcher"
	"github.com/pippinmole/upkeep.sh/server/internal/severity"
)

// Image scores (image_sbom_scores, migration 0015): per package list, the
// worst severity bucket plus counts per bucket, max CVSS and KEV
// (findings.ScoreOf), for every image whether a container uses it or not.
// Written here by the worker; read through image_scores(user)
// (imagescore_read.go, and the dashboard). The groups it counts are kept
// row by row in image_sbom_vulns (imagescore_vulns.go).

// ScoreResult reports ScoreImageSBOM.
type ScoreResult struct {
	Found   bool // the list exists and is ok
	Pending int  // versions not evaluated yet; nothing was written
	Score   findings.Score
}

// ScoreImageSBOM (re)computes and stores the score of one ok package
// list. It holds the list's image_sbom_state row lock, so it serialises
// with a rewrite of the list and with other scorings of it (the last
// commit always read the newest data). While any of the list's versions
// is not evaluated yet it writes nothing and reports Pending: the caller
// retries (a partial score would show fewer vulnerabilities than there
// are).
func (s *Store) ScoreImageSBOM(ctx context.Context, sbomID int64) (ScoreResult, error) {
	var res ScoreResult
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx)

	var id int64
	err = tx.QueryRow(ctx, `
		SELECT id FROM image_sbom_state WHERE id = $1 AND status = 'ok' FOR NO KEY UPDATE
	`, sbomID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return res, nil // gone, or never ok (a failure never replaces an ok list)
	}
	if err != nil {
		return res, err
	}
	res.Found = true

	// Package counts per (ecosystem, distro, release), for "not assessed"
	// (a release out of support or not in distro_releases is not assessed),
	// and the versions still waiting for the matcher.
	rows, err := tx.Query(ctx, `
		SELECT sv.ecosystem, sv.distro, sv.release, coalesce(dr.supported, false),
		       count(*), count(*) FILTER (WHERE sv.matcher_version IS NULL)
		FROM image_software isw JOIN software_versions sv ON sv.id = isw.software_id
		LEFT JOIN distro_releases dr ON dr.distro = sv.distro AND dr.codename = sv.release
		WHERE isw.sbom_id = $1
		GROUP BY sv.ecosystem, sv.distro, sv.release, dr.supported
	`, sbomID)
	if err != nil {
		return res, err
	}
	var packages, notAssessed int
	for rows.Next() {
		var (
			eco, distro, release string
			supported            bool
			n, pending           int
		)
		if err := rows.Scan(&eco, &distro, &release, &supported, &n, &pending); err != nil {
			rows.Close()
			return res, err
		}
		packages += n
		res.Pending += pending
		if !matcher.Assessed(eco, distro, release, supported) {
			notAssessed += n
		}
	}
	if err := rows.Err(); err != nil {
		return res, err
	}
	if res.Pending > 0 {
		return res, nil
	}

	vulnKeys := map[string]bool{}
	matches, err := loadListMatches(ctx, tx, []int64{sbomID}, vulnKeys)
	if err != nil {
		return res, err
	}
	cves, err := loadCVEs(ctx, tx, vulnKeys)
	if err != nil {
		return res, err
	}
	groups := findings.BuildImage(findings.Image{}, matches[sbomID], cves)
	sc := findings.ScoreGroups(groups)
	res.Score = sc

	var worst any
	if sc.Worst > 0 {
		worst = sc.Worst.String()
	}
	b := sc.ByBucket
	if _, err := tx.Exec(ctx, `
		INSERT INTO image_sbom_scores (sbom_id, package_count, not_assessed_count, pending_count, vuln_count,
			critical_count, high_count, medium_count, unknown_count, low_count, negligible_count,
			worst_severity, worst_severity_rank, top_severity_key, kev_count, fixable_count, max_cvss,
			matcher_version, computed_at)
		VALUES ($1, $2, $3, 0, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, now())
		ON CONFLICT (sbom_id) DO UPDATE SET
			package_count = EXCLUDED.package_count, not_assessed_count = EXCLUDED.not_assessed_count,
			pending_count = 0, vuln_count = EXCLUDED.vuln_count,
			critical_count = EXCLUDED.critical_count, high_count = EXCLUDED.high_count,
			medium_count = EXCLUDED.medium_count, unknown_count = EXCLUDED.unknown_count,
			low_count = EXCLUDED.low_count, negligible_count = EXCLUDED.negligible_count,
			worst_severity = EXCLUDED.worst_severity, worst_severity_rank = EXCLUDED.worst_severity_rank,
			top_severity_key = EXCLUDED.top_severity_key, kev_count = EXCLUDED.kev_count,
			fixable_count = EXCLUDED.fixable_count, max_cvss = EXCLUDED.max_cvss,
			matcher_version = EXCLUDED.matcher_version, computed_at = EXCLUDED.computed_at
	`, sbomID, packages, notAssessed, sc.Vulns,
		b[severity.BucketCritical], b[severity.BucketHigh], b[severity.BucketMedium],
		b[severity.BucketUnknown], b[severity.BucketLow], b[severity.BucketNegligible],
		worst, int(sc.Worst), int64(sc.TopKey), sc.KEV, sc.Fixable, sc.MaxCVSS, matcher.Version); err != nil {
		return res, err
	}
	if err := writeImageSBOMVulns(ctx, tx, sbomID, groups); err != nil {
		return res, err
	}
	return res, tx.Commit(ctx)
}

// ImageSBOMIDs returns the ok lists of an image key (the server's and
// every user's agent list).
func (s *Store) ImageSBOMIDs(ctx context.Context, key ImageKey) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id FROM image_sbom_state
		WHERE image_id = $1 AND os = $2 AND arch = $3 AND variant = $4 AND status = 'ok'
		ORDER BY id
	`, key.ImageID, key.OS, key.Arch, key.Variant)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// ImageSBOMsWithCVEsChangedSince returns the ok lists holding a version
// matched to a CVE whose enrichment (KEV, EPSS, CVSS) changed at or after
// since: the lists findings_rerank re-scores. Zero since = every list with
// a match.
func (s *Store) ImageSBOMsWithCVEsChangedSince(ctx context.Context, since time.Time) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT DISTINCT isw.sbom_id
		FROM cves c
		JOIN software_vulnerabilities sw ON sw.vuln_key = c.id
		JOIN image_software isw ON isw.software_id = sw.software_id
		WHERE c.updated_at >= $1
		ORDER BY isw.sbom_id
	`, since)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// StaleImageScores returns the ok lists whose score is missing, older than
// the list (rewritten since) or from an older matcher.Version (coverage
// may have changed), or counts vulnerabilities that have no
// image_sbom_vulns rows (scored before migration 0018: the backfill):
// image_score_sweep's work, and the backstop for a lost scoring job. At
// most limit ids, oldest list first.
func (s *Store) StaleImageScores(ctx context.Context, limit int) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT st.id
		FROM image_sbom_state st
		LEFT JOIN image_sbom_scores sc ON sc.sbom_id = st.id
		WHERE st.status = 'ok'
		  AND (sc.sbom_id IS NULL OR sc.computed_at < st.updated_at OR sc.matcher_version < $1
		       OR (sc.vuln_count > 0 AND NOT EXISTS (SELECT 1 FROM image_sbom_vulns v WHERE v.sbom_id = st.id)))
		ORDER BY st.id
		LIMIT $2
	`, matcher.Version, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}
