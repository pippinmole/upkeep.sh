package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// Image score read model: image_scores(user) (migration 0015) per image
// key, with why a list is or isn't there. The dashboard runs the same SQL;
// these are the Go shapes of its fleet, host and per-key variants.

// Image list statuses as image_scores reports them: SBOMStatusOK,
// SBOMStatusUnavailable, SBOMStatusError, or this one.
const SBOMStatusNone = "none" // nothing attempted yet ("no package list yet")

// ImageScore is one image key's list status and score as one user sees it.
type ImageScore struct {
	Key        ImageKey
	ListStatus string  // SBOMStatusOK | SBOMStatusUnavailable | SBOMStatusError | SBOMStatusNone
	ListReason *string // why there is no ok list
	ListSource *string // attestation | server-syft | agent-syft (ok only)
	SBOMID     *int64
	Distro     *string
	Release    *string
	DistroName *string
	// Scored: the ok list has a current score. False while it is being
	// matched / scored; the counts below are then NULL or stale.
	Scored   bool
	ScoredAt *time.Time

	Packages, NotAssessed, Pending *int
	Vulns                          *int
	WorstSeverity                  *string // NULL with Vulns 0 = no known vulnerabilities
	WorstSeverityRank              *int
	TopSeverityKey                 *int64
	Critical, High, Medium         *int
	Unknown, Low, Negligible       *int
	KEV                            *bool
	KEVCount, Fixable              *int
	MaxCVSS                        *float64
}

// Clean reports whether the image is known to have no vulnerabilities:
// an ok, scored list with no matches and every package assessed. An image
// without a list, or with unassessed packages, is never clean.
func (s ImageScore) Clean() bool {
	return s.ListStatus == SBOMStatusOK && s.Scored && s.Vulns != nil && *s.Vulns == 0 &&
		s.NotAssessed != nil && *s.NotAssessed == 0
}

const imageScoreCols = `s.image_id, s.os, s.arch, s.variant, s.list_status, s.list_reason, s.list_source,
	s.sbom_id, s.distro, s.release, s.distro_name, s.scored, s.scored_at,
	s.package_count, s.not_assessed_count, s.pending_count, s.vuln_count, s.worst_severity,
	s.worst_severity_rank, s.top_severity_key, s.critical_count, s.high_count, s.medium_count,
	s.unknown_count, s.low_count, s.negligible_count, s.kev, s.kev_count, s.fixable_count,
	s.max_cvss::float8`

func scanImageScore(r pgx.CollectableRow) (ImageScore, error) {
	var x ImageScore
	err := r.Scan(&x.Key.ImageID, &x.Key.OS, &x.Key.Arch, &x.Key.Variant, &x.ListStatus, &x.ListReason,
		&x.ListSource, &x.SBOMID, &x.Distro, &x.Release, &x.DistroName, &x.Scored, &x.ScoredAt,
		&x.Packages, &x.NotAssessed, &x.Pending, &x.Vulns, &x.WorstSeverity, &x.WorstSeverityRank,
		&x.TopSeverityKey, &x.Critical, &x.High, &x.Medium, &x.Unknown, &x.Low, &x.Negligible,
		&x.KEV, &x.KEVCount, &x.Fixable, &x.MaxCVSS)
	return x, err
}

// FleetImageScores returns every image key currently on one of the user's
// (not archived) hosts, most urgent first (top severity key, then image
// id). The fleet Images page's score columns.
func (s *Store) FleetImageScores(ctx context.Context, userID string) ([]ImageScore, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT `+imageScoreCols+`
		FROM image_scores($1) s
		WHERE (s.image_id, s.os, s.arch, s.variant) IN (
			SELECT hi.image_id, hi.os, hi.arch, hi.variant
			FROM host_images hi JOIN hosts h ON h.id = hi.host_id
			WHERE h.user_id = $1 AND h.archived_at IS NULL AND hi.removed_at IS NULL)
		ORDER BY s.top_severity_key DESC NULLS LAST, s.image_id, s.os, s.arch, s.variant
	`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanImageScore)
}

// HostImageScores returns the scores of the images currently on one host,
// as its owner sees them (the host Images / Containers tabs). Images
// never inspected on the host (platform unknown) have no key and are left
// out.
func (s *Store) HostImageScores(ctx context.Context, hostID string) ([]ImageScore, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT `+imageScoreCols+`
		FROM hosts h
		JOIN host_images hi ON hi.host_id = h.id AND hi.removed_at IS NULL
		CROSS JOIN LATERAL image_scores(h.user_id) s
		WHERE h.id = $1
		  AND s.image_id = hi.image_id AND s.os = hi.os AND s.arch = hi.arch AND s.variant = hi.variant
		ORDER BY s.top_severity_key DESC NULLS LAST, s.image_id
	`, hostID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanImageScore)
}

// ImageScoreOf returns one image key's score as userID sees it; nil when
// the key is not in container_images.
func (s *Store) ImageScoreOf(ctx context.Context, userID string, key ImageKey) (*ImageScore, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT `+imageScoreCols+`
		FROM image_scores($1) s
		WHERE s.image_id = $2 AND s.os = $3 AND s.arch = $4 AND s.variant = $5
	`, userID, key.ImageID, key.OS, key.Arch, key.Variant)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, scanImageScore)
	if err != nil || len(out) == 0 {
		return nil, err
	}
	return &out[0], nil
}
