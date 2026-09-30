package store

import (
	"context"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/findings"
)

// Container image findings (kind vulnerable_image, migration 0015): the
// store side of findings.BuildImage. ReconcileHostFindingsTx reconciles a
// host's image findings together with its package findings, in the same
// transaction and lifecycle; this file loads what they are built from.
//
// Scope (decided 2026-09-28): an image present on the host (open
// host_images range, inspected so its platform is known) that at least
// one current container on the host uses (open host_containers range,
// any state, image_id = the image). The package list is the one effective
// for the host's owner (image_sbom_effective): the server's list, else
// that user's agent list; another user's agent list is never used.

// Fact kinds of the Docker range tables (host_fact_state.kind); ingest
// uses the same names.
const (
	FactKindDockerContainers = "containers:docker"
	FactKindDockerImages     = "images:docker"
)

// ImageUseChanged reports whether this push opened or closed any
// container or image range, i.e. the set of images the host runs (or
// their tags / containers shown on its image findings) may have changed.
func (r SnapshotResult) ImageUseChanged() bool {
	for _, f := range r.Facts {
		if (f.Kind == FactKindDockerContainers || f.Kind == FactKindDockerImages) && f.Opened+f.Closed > 0 {
			return true
		}
	}
	return false
}

// hostImage is one image in a host's findings scope and the list used.
type hostImage struct {
	img    findings.Image
	sbomID int64
}

// loadHostImages returns the images in the host's findings scope that have
// an effective package list for workspaceID, ordered by image id.
func loadHostImages(ctx context.Context, tx pgx.Tx, hostID, workspaceID string) ([]hostImage, error) {
	rows, err := tx.Query(ctx, `
		SELECT hi.image_id, hi.os, hi.arch, hi.variant,
		       CASE WHEN cardinality(hi.repo_tags) > 0 THEN hi.repo_tags ELSE hi.repo_digests END,
		       c.names, e.sbom_id
		FROM host_images hi
		JOIN LATERAL (
			SELECT array_agg(DISTINCT hc.name ORDER BY hc.name) AS names
			FROM host_containers hc
			WHERE hc.host_id = hi.host_id AND hc.image_id = hi.image_id AND hc.removed_at IS NULL
		) c ON c.names IS NOT NULL
		JOIN image_sbom_effective($2) e
		  ON e.image_id = hi.image_id AND e.os = hi.os AND e.arch = hi.arch AND e.variant = hi.variant
		WHERE hi.host_id = $1 AND hi.removed_at IS NULL
		ORDER BY hi.image_id
	`, hostID, workspaceID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (hostImage, error) {
		var h hostImage
		err := r.Scan(&h.img.ID, &h.img.OS, &h.img.Arch, &h.img.Variant, &h.img.Refs, &h.img.Containers, &h.sbomID)
		return h, err
	})
}

// imageListsPending reports whether any of the lists holds a version the
// matcher has not evaluated yet (reconcile would resolve findings the
// pending match job reopens; see ErrUnevaluated).
func imageListsPending(ctx context.Context, q pgx.Tx, sbomIDs []int64) (bool, error) {
	if len(sbomIDs) == 0 {
		return false, nil
	}
	var pending bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM image_software isw
			JOIN software_versions sv ON sv.id = isw.software_id
			WHERE isw.sbom_id = ANY($1) AND sv.matcher_version IS NULL)
	`, sbomIDs).Scan(&pending)
	return pending, err
}

// loadListMatches returns the current matches of the given lists' versions
// per list id, in the shape findings.BuildImage takes, and adds their
// vuln_keys to vulnKeys.
func loadListMatches(ctx context.Context, q pgx.Tx, sbomIDs []int64, vulnKeys map[string]bool) (map[int64][]findings.HostMatch, error) {
	out := map[int64][]findings.HostMatch{}
	if len(sbomIDs) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `
		SELECT isw.sbom_id, sv.id, sv.ecosystem, sv.name, sv.match_source, sv.match_version, COALESCE(sv.kernel_release, ''),
		       sw.vuln_key, sw.advisory_ids, sw.fixed_version, COALESCE(sw.fix_channel, ''),
		       COALESCE(sw.fix_advisory_id, ''), sw.distro_severity
		FROM image_software isw
		JOIN software_versions sv ON sv.id = isw.software_id
		JOIN software_vulnerabilities sw ON sw.software_id = sv.id
		WHERE isw.sbom_id = ANY($1) AND sv.match_source IS NOT NULL
	`, sbomIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id int64
			m  findings.HostMatch
		)
		if err := rows.Scan(&id, &m.SoftwareID, &m.Ecosystem, &m.Package, &m.Source, &m.Version, &m.KernelRelease,
			&m.Match.VulnKey, &m.Match.AdvisoryIDs, &m.Match.FixedVersion, &m.Match.FixChannel,
			&m.Match.FixAdvisoryID, &m.Match.Severity); err != nil {
			return nil, err
		}
		out[id] = append(out[id], m)
		vulnKeys[m.Match.VulnKey] = true
	}
	return out, rows.Err()
}

// buildImageFindings is the image half of a host reconcile: the desired
// vulnerable_image findings for the host's images in scope.
func buildImageFindings(images []hostImage, matches map[int64][]findings.HostMatch, cves map[string]findings.CVE) []findings.Desired {
	var out []findings.Desired
	for _, h := range images {
		out = append(out, findings.BuildImage(h.img, matches[h.sbomID], cves)...)
	}
	return out
}

func sbomIDsOf(images []hostImage) []int64 {
	ids := make([]int64, 0, len(images))
	for _, h := range images {
		ids = append(ids, h.sbomID)
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

// HostsWithImageSoftware returns the hosts that currently have an image
// (open host_images range) whose ok package list, server or agent, holds
// any of the given versions: the image-side counterpart of
// HostsWithSoftware, through the image_software reverse index. It may
// include hosts whose owner's effective list is another one; their
// reconcile then changes nothing.
func (s *Store) HostsWithImageSoftware(ctx context.Context, ids []int64) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT DISTINCT hi.host_id::text
		FROM image_sbom_state st
		JOIN host_images hi
		  ON hi.image_id = st.image_id AND hi.os = st.os AND hi.arch = st.arch AND hi.variant = st.variant
		 AND hi.removed_at IS NULL
		WHERE st.status = 'ok'
		  AND st.id IN (SELECT sbom_id FROM image_software WHERE software_id = ANY($1))
	`, ids)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// HostsWithImage returns the hosts that currently have the image key
// (open host_images range): the hosts to reconcile after its package list
// was written or its score changed.
func (s *Store) HostsWithImage(ctx context.Context, key ImageKey) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT DISTINCT host_id::text FROM host_images
		WHERE image_id = $1 AND os = $2 AND arch = $3 AND variant = $4 AND removed_at IS NULL
	`, key.ImageID, key.OS, key.Arch, key.Variant)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
