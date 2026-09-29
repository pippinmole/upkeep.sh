package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Bookkeeping for the server's own package lists (owner NULL), produced by
// the image_sbom worker (internal/imagesbom, jobs "image_sbom"): which
// image keys need an attempt, and the repo digests to fetch them by.

// Reasons the image_sbom worker records (image_sbom_state.reason). They
// are shown to users as is and are stable, so other producers can select
// on them: server-side Syft (docs/tasks/phase-2a-image-vulns.md) picks up
//
//	WHERE owner_workspace_id IS NULL AND status = 'unavailable' AND reason = SBOMReasonNoAttestation
//
// and the agent round trip the SBOMReasonPrivate ones.
const (
	SBOMReasonNoAttestation = "registry has no SBOM attestation for this image"
	SBOMReasonPrivate       = "private or local image, needs the agent"
	SBOMReasonFetchDisabled = "image fetching disabled on this server"
)

// ImageSBOMState is the attempt bookkeeping of one list.
type ImageSBOMState struct {
	Status        string
	Reason        string
	Attempts      int
	NextAttemptAt *time.Time
}

// ServerImageSBOMState returns the server's (owner NULL) state row for
// key, nil when nothing was attempted yet.
func (s *Store) ServerImageSBOMState(ctx context.Context, key ImageKey) (*ImageSBOMState, error) {
	var (
		st     ImageSBOMState
		reason *string
	)
	err := s.Pool.QueryRow(ctx, `
		SELECT status, reason, attempts, next_attempt_at FROM image_sbom_state
		WHERE owner_workspace_id IS NULL AND image_id = $1 AND os = $2 AND arch = $3 AND variant = $4
	`, key.ImageID, key.OS, key.Arch, key.Variant).Scan(&st.Status, &reason, &st.Attempts, &st.NextAttemptAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	st.Reason = deref(reason)
	return &st, err
}

// ImageRepoDigests returns the repo digests any host currently reports for
// the image key ("postgres@sha256:…"), sorted and de-duplicated.
func (s *Store) ImageRepoDigests(ctx context.Context, key ImageKey) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT DISTINCT d
		FROM host_images hi, unnest(hi.repo_digests) AS d
		WHERE hi.image_id = $1 AND hi.removed_at IS NULL
		  AND hi.os = $2 AND hi.arch = $3 AND hi.variant = $4
		ORDER BY d
	`, key.ImageID, key.OS, key.Arch, key.Variant)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// ImageKeysForSBOMTx returns the image keys whose host_images ranges
// snapshotID opened on hostID with a repo digest, and that need a server
// package list attempt: no server row yet, or a failed one that isn't on a
// retry timer (e.g. "private or local image") while this range brings a
// repo digest no other host (or this host before) reported for the key.
// Keys with an ok list are never returned, and keys on a timer are left
// to the sweep. Runs in the snapshot transaction (ingest).
func ImageKeysForSBOMTx(ctx context.Context, tx pgx.Tx, hostID, snapshotID string) ([]ImageKey, error) {
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT hi.image_id, hi.os, hi.arch, hi.variant
		FROM host_images hi
		LEFT JOIN image_sbom_state s ON s.owner_workspace_id IS NULL
			AND s.image_id = hi.image_id AND s.os = hi.os AND s.arch = hi.arch AND s.variant = hi.variant
		WHERE hi.host_id = $1 AND hi.first_seen_snapshot_id = $2 AND hi.removed_at IS NULL
		  AND hi.os IS NOT NULL AND cardinality(hi.repo_digests) > 0
		  AND (s.id IS NULL OR (s.status <> 'ok' AND s.next_attempt_at IS NULL AND EXISTS (
				SELECT unnest(hi.repo_digests)
				EXCEPT
				SELECT unnest(o.repo_digests) FROM host_images o
				WHERE o.image_id = hi.image_id AND o.os = hi.os AND o.arch = hi.arch AND o.variant = hi.variant
				  AND NOT (o.host_id = hi.host_id AND o.first_seen_at = hi.first_seen_at)
				  AND (o.removed_at IS NULL OR o.host_id = hi.host_id))))
		ORDER BY 1, 2, 3, 4
	`, hostID, snapshotID)
	if err != nil {
		return nil, err
	}
	return collectImageKeys(rows)
}

// ImageSBOMSweep returns up to limit image keys the image_sbom worker
// should (re)try: server rows whose retry time has come, image keys some
// host reports with a repo digest but that have no server row (a lost
// enqueue), and, when retryDisabled, rows recorded while image fetching
// was disabled (it has been enabled since).
func (s *Store) ImageSBOMSweep(ctx context.Context, limit int, retryDisabled bool) ([]ImageKey, error) {
	rows, err := s.Pool.Query(ctx, `
		(SELECT image_id, os, arch, variant FROM image_sbom_state
		 WHERE owner_workspace_id IS NULL AND status <> 'ok'
		   AND (next_attempt_at <= now() OR ($2 AND reason = $3 AND next_attempt_at IS NULL)))
		UNION
		(SELECT hi.image_id, hi.os, hi.arch, hi.variant FROM host_images hi
		 WHERE hi.removed_at IS NULL AND hi.os IS NOT NULL AND cardinality(hi.repo_digests) > 0
		   AND NOT EXISTS (SELECT 1 FROM image_sbom_state s WHERE s.owner_workspace_id IS NULL
			AND s.image_id = hi.image_id AND s.os = hi.os AND s.arch = hi.arch AND s.variant = hi.variant))
		ORDER BY 1, 2, 3, 4
		LIMIT $1
	`, limit, retryDisabled, SBOMReasonFetchDisabled)
	if err != nil {
		return nil, err
	}
	return collectImageKeys(rows)
}

// ImageScanSweep returns up to limit image keys on server-side Syft's work
// list (server rows unavailable with SBOMReasonNoAttestation) that some
// host still reports with a repo digest: rows image_sbom handed over
// whose image_scan job was lost, and rows recorded before scanning was
// enabled. Retries of failed scans aren't here: they are error rows on a
// timer, which ImageSBOMSweep returns (the attestation is checked first).
func (s *Store) ImageScanSweep(ctx context.Context, limit int) ([]ImageKey, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT s.image_id, s.os, s.arch, s.variant FROM image_sbom_state s
		WHERE s.owner_user_id IS NULL AND s.status = 'unavailable' AND s.reason = $2
		  AND EXISTS (SELECT 1 FROM host_images hi
			WHERE hi.image_id = s.image_id AND hi.os = s.os AND hi.arch = s.arch AND hi.variant = s.variant
			  AND hi.removed_at IS NULL AND cardinality(hi.repo_digests) > 0)
		ORDER BY 1, 2, 3, 4
		LIMIT $1
	`, limit, SBOMReasonNoAttestation)
	if err != nil {
		return nil, err
	}
	return collectImageKeys(rows)
}

func collectImageKeys(rows pgx.Rows) ([]ImageKey, error) {
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (ImageKey, error) {
		var k ImageKey
		err := row.Scan(&k.ImageID, &k.OS, &k.Arch, &k.Variant)
		return k, err
	})
}
