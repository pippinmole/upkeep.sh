package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/purl"
)

// ImageSBOMRef is one stored package list.
type ImageSBOMRef struct {
	SBOMID           int64
	Key              ImageKey
	OwnerWorkspaceID string // "" = fleet-wide server list
	Source           string
}

// ImageSoftwareRow is one package of an image list.
type ImageSoftwareRow struct {
	SoftwareID                 int64
	Ecosystem, Distro, Release string
	Name, Version, Arch        string
	Paths                      []string
}

// EffectiveImageSBOM returns the list user workspaceID sees for key: the
// server's list if it is ok, else the user's agent list if that is ok
// (image_sbom_effective, migration 0014). nil when neither exists; why is
// then read from image_sbom_state. workspaceID "" sees server lists only.
func (s *Store) EffectiveImageSBOM(ctx context.Context, workspaceID string, key ImageKey) (*ImageSBOMRef, error) {
	var (
		r     = ImageSBOMRef{Key: key}
		owner *string
	)
	err := s.Pool.QueryRow(ctx, `
		SELECT e.sbom_id, e.owner_workspace_id::text, e.source
		FROM image_sbom_effective($1) e
		WHERE e.image_id = $2 AND e.os = $3 AND e.arch = $4 AND e.variant = $5
	`, nilIfEmpty(workspaceID), key.ImageID, key.OS, key.Arch, key.Variant).Scan(&r.SBOMID, &owner, &r.Source)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.OwnerWorkspaceID = deref(owner)
	return &r, nil
}

// ImageSoftware returns the packages of one list, ordered by ecosystem,
// name, version.
func (s *Store) ImageSoftware(ctx context.Context, sbomID int64) ([]ImageSoftwareRow, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT sv.id, sv.ecosystem, sv.distro, sv.release, sv.name, sv.version, sv.arch, isw.paths
		FROM image_software isw
		JOIN software_versions sv ON sv.id = isw.software_id
		WHERE isw.sbom_id = $1
		ORDER BY sv.ecosystem, sv.name, sv.version, sv.arch
	`, sbomID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (ImageSoftwareRow, error) {
		var r ImageSoftwareRow
		err := row.Scan(&r.SoftwareID, &r.Ecosystem, &r.Distro, &r.Release, &r.Name, &r.Version, &r.Arch, &r.Paths)
		return r, err
	})
}

// ImageSBOMsContaining returns every ok list containing any of the given
// versions (reverse lookup through image_software_software_idx): the
// image-side counterpart of "hosts having version X", for reconciling
// image findings when a version's matches change. Ordered by list id.
func (s *Store) ImageSBOMsContaining(ctx context.Context, softwareIDs []int64) ([]ImageSBOMRef, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT st.id, st.image_id, st.os, st.arch, st.variant, st.owner_workspace_id::text, st.source
		FROM image_sbom_state st
		WHERE st.status = 'ok'
		  AND st.id IN (SELECT sbom_id FROM image_software WHERE software_id = ANY($1))
		ORDER BY st.id
	`, softwareIDs)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (ImageSBOMRef, error) {
		var (
			r     ImageSBOMRef
			owner *string
		)
		err := row.Scan(&r.SBOMID, &r.Key.ImageID, &r.Key.OS, &r.Key.Arch, &r.Key.Variant, &owner, &r.Source)
		r.OwnerWorkspaceID = deref(owner)
		return r, err
	})
}

// DistroReleaseIndex loads distro_releases as a version -> codename index
// for purl.Map / purl.ReleaseFor.
func (s *Store) DistroReleaseIndex(ctx context.Context) (purl.ReleaseIndex, error) {
	rows, err := s.Pool.Query(ctx, `SELECT distro, version, codename FROM distro_releases`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ix := purl.ReleaseIndex{}
	for rows.Next() {
		var k purl.ReleaseKey
		var codename string
		if err := rows.Scan(&k.Distro, &k.Version, &codename); err != nil {
			return nil, err
		}
		ix[k] = codename
	}
	return ix, rows.Err()
}
