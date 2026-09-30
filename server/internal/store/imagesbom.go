package store

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/inventory"
	"github.com/pippinmole/upkeep.sh/server/internal/purl"
)

// Container image package lists (migration 0014,
// docs/decisions/container-image-vulnerabilities.md). An image's packages
// are interned into software_versions exactly like a host's (internVersions), so the matcher
// and its triggers cover them unchanged; image_software is the plain set
// per list, image_sbom_state the list's provenance and attempt bookkeeping.

// ImageKey identifies image content: the container_images key.
type ImageKey struct{ ImageID, OS, Arch, Variant string }

// Package list sources (image_sbom_state.source).
const (
	SBOMSourceAttestation = "attestation" // registry SBOM attestation, by digest (server)
	SBOMSourceServerSyft  = "server-syft" // image pulled by digest, Syft on the server
	SBOMSourceAgentSyft   = "agent-syft"  // Syft run by a user's agent on local layers
)

// Package list statuses (image_sbom_state.status).
const (
	SBOMStatusOK          = "ok"
	SBOMStatusUnavailable = "unavailable" // e.g. private or local image, waiting for the agent
	SBOMStatusError       = "error"
)

// ImagePackage is one SBOM entry mapped to the interned key (purl.Map),
// with the paths in the image it was found at.
type ImagePackage struct {
	purl.Package
	Paths []string
}

// ImageSBOMInput is one complete package list for an image key.
type ImageSBOMInput struct {
	Key ImageKey
	// OwnerWorkspaceID is "" for a list the server obtained itself
	// (attestation, server-syft: fleet-wide) and the user's id for an
	// agent's list (agent-syft).
	OwnerWorkspaceID string
	Source           string
	ToolName         string
	ToolVersion      string
	// GeneratedAt is the SBOM's creation time; zero = now.
	GeneratedAt time.Time
	// OS is the image's os-release (zero when none), Release the key its
	// distro packages were interned under (purl.ReleaseFor).
	OS       purl.OSRelease
	Release  string
	Packages []ImagePackage

	// AfterWrite, if set, runs inside the transaction before commit, as
	// for SnapshotInput: the caller enqueues match_versions for
	// RematchSoftwareIDs with River's InsertTx (jobs.EnqueueAfterImageSBOM).
	AfterWrite func(ctx context.Context, tx pgx.Tx, res ImageSBOMResult) error
}

// ImageSBOMResult reports what WriteImageSBOM did.
type ImageSBOMResult struct {
	SBOMID   int64
	Key      ImageKey // the list's image key (ImageSBOMInput.Key)
	Packages int      // distinct interned versions in the list
	// Added / Removed are software ids that entered or left this list
	// (both empty on an idempotent rewrite).
	Added, Removed []int64
	// NewSoftwareIDs were first interned by this write; ResetSoftwareIDs
	// had their inferred source replaced by a real one (see
	// InventoryResult).
	NewSoftwareIDs, ResetSoftwareIDs []int64
}

// RematchSoftwareIDs are the versions this write needs evaluated.
func (r ImageSBOMResult) RematchSoftwareIDs() []int64 {
	return append(slices.Clone(r.NewSoftwareIDs), r.ResetSoftwareIDs...)
}

func (in ImageSBOMInput) validate() error {
	switch in.Source {
	case SBOMSourceAttestation, SBOMSourceServerSyft:
		if in.OwnerWorkspaceID != "" {
			return fmt.Errorf("image sbom: source %s is fleet-wide, owner must be empty", in.Source)
		}
	case SBOMSourceAgentSyft:
		if in.OwnerWorkspaceID == "" {
			return errors.New("image sbom: an agent list needs its owner")
		}
	default:
		return fmt.Errorf("image sbom: unknown source %q", in.Source)
	}
	if in.Key.ImageID == "" {
		return errors.New("image sbom: empty image id")
	}
	return nil
}

// WriteImageSBOM stores a complete package list for (image key, owner) in
// one transaction: interns every package (enqueueing matching through
// AfterWrite), marks the list ok (resetting the attempt bookkeeping) and
// replaces its image_software set atomically. Idempotent: writing the same
// list again changes nothing but the state row's timestamps. The image key
// must already be in container_images.
func (s *Store) WriteImageSBOM(ctx context.Context, in ImageSBOMInput) (res ImageSBOMResult, err error) {
	if err := in.validate(); err != nil {
		return res, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx)

	paths, err := internImagePackages(ctx, tx, in.Packages, &res)
	if err != nil {
		return res, err
	}
	res.Packages, res.Key = len(paths), in.Key

	generated := in.GeneratedAt
	if generated.IsZero() {
		generated = time.Now()
	}
	// Upserting the state row first also locks it, so concurrent writes of
	// one list serialise.
	err = tx.QueryRow(ctx, `
		INSERT INTO image_sbom_state
			(image_id, os, arch, variant, owner_workspace_id, status, source, tool_name, tool_version,
			 generated_at, package_count, distro, distro_version, release, distro_name,
			 attempts, last_attempt_at)
		VALUES ($1, $2, $3, $4, $5, 'ok', $6, $7, $8, $9, $10, $11, $12, $13, $14, 0, now())
		ON CONFLICT ON CONSTRAINT image_sbom_state_key DO UPDATE SET
			status = 'ok', reason = NULL,
			source = EXCLUDED.source, tool_name = EXCLUDED.tool_name, tool_version = EXCLUDED.tool_version,
			generated_at = EXCLUDED.generated_at, package_count = EXCLUDED.package_count,
			distro = EXCLUDED.distro, distro_version = EXCLUDED.distro_version,
			release = EXCLUDED.release, distro_name = EXCLUDED.distro_name,
			attempts = 0, last_attempt_at = now(), next_attempt_at = NULL, updated_at = now()
		RETURNING id
	`, in.Key.ImageID, in.Key.OS, in.Key.Arch, in.Key.Variant, nilIfEmpty(in.OwnerWorkspaceID),
		in.Source, nilIfEmpty(in.ToolName), nilIfEmpty(in.ToolVersion), generated, res.Packages,
		nilIfEmpty(in.OS.ID), nilIfEmpty(in.OS.VersionID), nilIfEmpty(in.Release), nilIfEmpty(in.OS.PrettyName),
	).Scan(&res.SBOMID)
	if err != nil {
		return res, fmt.Errorf("image sbom state: %w", err)
	}

	if err := replaceImageSoftware(ctx, tx, res.SBOMID, paths, &res); err != nil {
		return res, err
	}
	if in.AfterWrite != nil {
		if err := in.AfterWrite(ctx, tx, res); err != nil {
			return res, err
		}
	}
	return res, tx.Commit(ctx)
}

type imageScope struct{ ecosystem, distro, release string }

type imagePkgKey struct {
	imageScope
	name, version, arch string
}

// internImagePackages interns pkgs, one inventory.Set per (ecosystem,
// distro, release) in a fixed order, through the same internVersions as
// host ingest. It returns the paths per interned id (entries sharing an
// interned key merged, sorted, de-duplicated).
func internImagePackages(ctx context.Context, tx pgx.Tx, pkgs []ImagePackage, res *ImageSBOMResult) (map[int64][]string, error) {
	items := map[imageScope][]inventory.Item{}
	pathsByKey := map[imagePkgKey][]string{}
	for _, p := range pkgs {
		sc := imageScope{p.Ecosystem, p.Distro, p.Release}
		items[sc] = append(items[sc], p.Item)
		k := imagePkgKey{sc, p.Item.Name, p.Item.Version, p.Item.Arch}
		pathsByKey[k] = append(pathsByKey[k], p.Paths...)
	}
	scopes := make([]imageScope, 0, len(items))
	for sc := range items {
		scopes = append(scopes, sc)
	}
	slices.SortFunc(scopes, func(a, b imageScope) int {
		return cmp.Or(cmp.Compare(a.ecosystem, b.ecosystem), cmp.Compare(a.distro, b.distro),
			cmp.Compare(a.release, b.release))
	})

	out := map[int64][]string{}
	for _, sc := range scopes {
		set := inventory.NewSet(sc.ecosystem, sc.distro, sc.release, items[sc])
		ids, inserted, reset, err := internVersions(ctx, tx, set)
		if err != nil {
			return nil, fmt.Errorf("intern %s/%s/%s: %w", sc.ecosystem, sc.distro, sc.release, err)
		}
		res.NewSoftwareIDs = append(res.NewSoftwareIDs, inserted...)
		res.ResetSoftwareIDs = append(res.ResetSoftwareIDs, reset...)
		for i, it := range set.Items {
			ps := slices.Clone(pathsByKey[imagePkgKey{sc, it.Name, it.Version, it.Arch}])
			slices.Sort(ps)
			ps = slices.Compact(ps)
			if ps == nil {
				ps = []string{}
			}
			out[ids[i]] = ps
		}
	}
	return out, nil
}

// replaceImageSoftware makes sbomID's image_software rows exactly paths:
// removes the ids not in it, inserts new ones, updates changed paths.
func replaceImageSoftware(ctx context.Context, tx pgx.Tx, sbomID int64, paths map[int64][]string, res *ImageSBOMResult) error {
	rows, err := tx.Query(ctx, `SELECT software_id FROM image_software WHERE sbom_id = $1`, sbomID)
	if err != nil {
		return err
	}
	old, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return err
	}
	ids := make([]int64, 0, len(paths))
	for id := range paths {
		ids = append(ids, id)
	}
	res.Added, res.Removed = inventory.Diff(old, ids)

	if len(res.Removed) > 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM image_software WHERE sbom_id = $1 AND software_id = ANY($2)`,
			sbomID, res.Removed); err != nil {
			return err
		}
	}
	if len(ids) == 0 {
		return nil
	}
	type row struct {
		ID    int64    `json:"id"`
		Paths []string `json:"paths"`
	}
	slices.Sort(ids)
	recs := make([]row, len(ids))
	for i, id := range ids {
		recs[i] = row{id, paths[id]}
	}
	doc, err := json.Marshal(recs)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO image_software (sbom_id, software_id, paths)
		SELECT $1, t.id, t.paths FROM jsonb_to_recordset($2::jsonb) AS t(id bigint, paths text[])
		ORDER BY t.id
		ON CONFLICT (sbom_id, software_id) DO UPDATE SET paths = EXCLUDED.paths
		WHERE image_software.paths IS DISTINCT FROM EXCLUDED.paths
	`, sbomID, doc)
	return err
}

// ImageSBOMFailure records a failed or impossible attempt at a list.
type ImageSBOMFailure struct {
	Key              ImageKey
	OwnerWorkspaceID string // "" = the server's own attempt
	Status           string // SBOMStatusUnavailable | SBOMStatusError
	Reason           string // shown to users as is
	// NextAttemptAt is when to try again; nil = not on a timer.
	NextAttemptAt *time.Time
}

// RecordImageSBOMFailure notes a failed attempt: status, reason, attempts
// + 1, last/next attempt. It never overwrites an ok list (a good list
// stays good; image content doesn't change) and then reports false.
func (s *Store) RecordImageSBOMFailure(ctx context.Context, f ImageSBOMFailure) (bool, error) {
	if f.Status != SBOMStatusUnavailable && f.Status != SBOMStatusError {
		return false, fmt.Errorf("image sbom failure: bad status %q", f.Status)
	}
	if f.Reason == "" {
		return false, errors.New("image sbom failure: empty reason")
	}
	var id int64
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO image_sbom_state
			(image_id, os, arch, variant, owner_workspace_id, status, reason, attempts, last_attempt_at, next_attempt_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 1, now(), $8)
		ON CONFLICT ON CONSTRAINT image_sbom_state_key DO UPDATE SET
			status = EXCLUDED.status, reason = EXCLUDED.reason,
			attempts = image_sbom_state.attempts + 1, last_attempt_at = now(),
			next_attempt_at = EXCLUDED.next_attempt_at, updated_at = now()
		WHERE image_sbom_state.status <> 'ok'
		RETURNING id
	`, f.Key.ImageID, f.Key.OS, f.Key.Arch, f.Key.Variant, nilIfEmpty(f.OwnerWorkspaceID),
		f.Status, f.Reason, f.NextAttemptAt).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
