package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/hostfacts"
)

// Docker storage (migration 0013, PROTOCOL.md "Docker sections"). The
// container and image ranges go through applyFactSet like the other host
// facts (kinds "containers:docker" and "images:docker"); this file holds
// the parts that aren't plain host ranges: the fleet-wide image content
// table, the per-host engine / networks row, and Swarm services, whose
// ranges belong to a cluster rather than a host.

// ContainerImage is one fully inspected image's content, interned into
// container_images by (image_id, os, arch, variant). Only built from ok,
// non-partial image entries.
type ContainerImage struct {
	ImageID, OS, Arch, Variant string
	Created                    *time.Time
	Layers                     []string
	Labels                     map[string]string
}

// DockerEngineInput is the docker_engine collector's section (only set
// when that collector was ok).
type DockerEngineInput struct {
	Version, APIVersion, StorageDriver, ImageStore string
	Rootless                                       bool
	// Swarm is nil when the node isn't an active or locked Swarm member.
	Swarm *DockerSwarmInput
}

type DockerSwarmInput struct {
	State, NodeID, ClusterID, Role string
}

// DockerNetworksInput is the docker_networks collector's section (only
// set when that collector was ok). Networks is stored as JSON as is.
type DockerNetworksInput struct {
	Networks  any
	Truncated bool
}

// SwarmServicesInput is an ok swarm_services section from a manager of
// ClusterID. Set is a hostfacts.SwarmServicesTable set.
type SwarmServicesInput struct {
	ClusterID string
	Set       hostfacts.Set
}

// internContainerImages inserts image content not seen before, in one
// statement. Rows are immutable (content-addressed), so an existing row is
// never updated. Rows are inserted in key order so that concurrent pushes
// lock them in the same order.
func internContainerImages(ctx context.Context, tx pgx.Tx, images []ContainerImage) error {
	if len(images) == 0 {
		return nil
	}
	type rec struct {
		ImageID string            `json:"image_id"`
		OS      string            `json:"os"`
		Arch    string            `json:"arch"`
		Variant string            `json:"variant"`
		Created *time.Time        `json:"created"`
		Layers  []string          `json:"layers"`
		Labels  map[string]string `json:"labels"`
	}
	recs := make([]rec, len(images))
	for i, im := range images {
		recs[i] = rec(im)
		if recs[i].Layers == nil {
			recs[i].Layers = []string{}
		}
		if recs[i].Labels == nil {
			recs[i].Labels = map[string]string{}
		}
	}
	b, err := json.Marshal(recs)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO container_images (image_id, os, arch, variant, created, layers, labels)
		SELECT x.image_id, x.os, x.arch, x.variant, x.created,
		       ARRAY(SELECT l FROM jsonb_array_elements_text(x.layers) WITH ORDINALITY AS t(l, n) ORDER BY n),
		       x.labels
		FROM jsonb_to_recordset($1::jsonb)
		     AS x(image_id text, os text, arch text, variant text, created timestamptz, layers jsonb, labels jsonb)
		ORDER BY x.image_id, x.os, x.arch, x.variant
		ON CONFLICT (image_id, os, arch, variant) DO NOTHING
	`, string(b)); err != nil {
		return fmt.Errorf("intern container images: %w", err)
	}
	return nil
}

// applyDockerHost writes the host_docker parts this push was ok for, each
// only when the push is newer than what the row holds (an out-of-order
// older push must not roll it back).
func applyDockerHost(ctx context.Context, tx pgx.Tx, hostID, snapshotID string, at time.Time, eng *DockerEngineInput, nets *DockerNetworksInput) error {
	if eng != nil {
		sw := eng.Swarm
		if sw == nil {
			sw = &DockerSwarmInput{}
		}
		// While a manager is locked the engine reports no node / cluster /
		// role: keep the last known membership rather than dropping it.
		if _, err := tx.Exec(ctx, `
			INSERT INTO host_docker (host_id, engine_version, api_version, storage_driver, image_store, rootless,
				swarm_state, swarm_node_id, swarm_cluster_id, swarm_role, engine_collected_at, engine_snapshot_id)
			VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''), $6,
				NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''), NULLIF($10, ''), $11, $12)
			ON CONFLICT (host_id) DO UPDATE SET
				engine_version   = EXCLUDED.engine_version,
				api_version      = EXCLUDED.api_version,
				storage_driver   = EXCLUDED.storage_driver,
				image_store      = EXCLUDED.image_store,
				rootless         = EXCLUDED.rootless,
				swarm_state      = EXCLUDED.swarm_state,
				swarm_node_id    = CASE WHEN EXCLUDED.swarm_state = 'locked'
					THEN coalesce(EXCLUDED.swarm_node_id, host_docker.swarm_node_id) ELSE EXCLUDED.swarm_node_id END,
				swarm_cluster_id = CASE WHEN EXCLUDED.swarm_state = 'locked'
					THEN coalesce(EXCLUDED.swarm_cluster_id, host_docker.swarm_cluster_id) ELSE EXCLUDED.swarm_cluster_id END,
				swarm_role       = CASE WHEN EXCLUDED.swarm_state = 'locked'
					THEN coalesce(EXCLUDED.swarm_role, host_docker.swarm_role) ELSE EXCLUDED.swarm_role END,
				engine_collected_at = EXCLUDED.engine_collected_at,
				engine_snapshot_id  = EXCLUDED.engine_snapshot_id
			WHERE host_docker.engine_collected_at IS NULL OR host_docker.engine_collected_at < EXCLUDED.engine_collected_at
		`, hostID, eng.Version, eng.APIVersion, eng.StorageDriver, eng.ImageStore, eng.Rootless,
			sw.State, sw.NodeID, sw.ClusterID, sw.Role, at, snapshotID); err != nil {
			return fmt.Errorf("docker engine: %w", err)
		}
	}
	if nets != nil {
		b, err := json.Marshal(nets.Networks)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO host_docker (host_id, networks, networks_truncated, networks_collected_at, networks_snapshot_id)
			VALUES ($1, $2::jsonb, $3, $4, $5)
			ON CONFLICT (host_id) DO UPDATE SET
				networks              = EXCLUDED.networks,
				networks_truncated    = EXCLUDED.networks_truncated,
				networks_collected_at = EXCLUDED.networks_collected_at,
				networks_snapshot_id  = EXCLUDED.networks_snapshot_id
			WHERE host_docker.networks_collected_at IS NULL OR host_docker.networks_collected_at < EXCLUDED.networks_collected_at
		`, hostID, string(b), nets.Truncated, at, snapshotID); err != nil {
			return fmt.Errorf("docker networks: %w", err)
		}
	}
	return nil
}

// applySwarmServices reconciles a cluster's swarm_services ranges with a
// manager's ok push, with swarm_clusters as the cluster's bookkeeping
// (like host_fact_state): stale pushes (not newer than the cluster's last
// applied one, from any manager) are ignored, an unchanged set hash only
// moves confirmed_at, a truncated set is additive. Clusters are scoped by
// the pushing host's user. The cluster row is locked for the diff, so
// managers of one cluster pushing at once serialize.
func applySwarmServices(ctx context.Context, tx pgx.Tx, hostID, snapshotID string, at time.Time, in SwarmServicesInput) (FactResult, error) {
	res := FactResult{Kind: in.Set.Kind}
	var workspaceID string
	if err := tx.QueryRow(ctx, `SELECT workspace_id FROM hosts WHERE id = $1`, hostID).Scan(&workspaceID); err != nil {
		return res, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO swarm_clusters (workspace_id, cluster_id, confirmed_at, changed_at, first_seen_at)
		VALUES ($1, $2, '-infinity', '-infinity', $3)
		ON CONFLICT (workspace_id, cluster_id) DO NOTHING
	`, workspaceID, in.ClusterID, at); err != nil {
		return res, err
	}
	var (
		curHash *string
		stale   bool
	)
	if err := tx.QueryRow(ctx, `
		SELECT set_hash, confirmed_at >= $3 FROM swarm_clusters WHERE workspace_id = $1 AND cluster_id = $2 FOR UPDATE
	`, workspaceID, in.ClusterID, at).Scan(&curHash, &stale); err != nil {
		return res, err
	}
	if stale {
		res.Outcome = InventoryStale
		return res, nil
	}
	changed := false
	if !in.Set.Additive && curHash != nil && *curHash == in.Set.Hash {
		res.Outcome = InventoryUnchanged
	} else {
		res.Outcome = InventoryDiffed
		owner := rangeOwner{cols: []string{"workspace_id", "cluster_id"}, vals: []any{workspaceID, in.ClusterID}}
		var err error
		if res.Opened, res.Closed, res.Updated, err = reconcileRanges(ctx, tx, owner, snapshotID, at, in.Set); err != nil {
			return res, err
		}
		changed = res.Opened+res.Closed > 0
	}
	var hash any = in.Set.Hash
	if in.Set.Additive {
		hash = nil
	}
	_, err := tx.Exec(ctx, `
		UPDATE swarm_clusters SET
			set_hash              = $3,
			confirmed_at          = $4,
			confirmed_snapshot_id = $5,
			last_manager_host_id  = $6,
			changed_at = CASE WHEN $7 OR changed_at = '-infinity' THEN $4 ELSE changed_at END
		WHERE workspace_id = $1 AND cluster_id = $2
	`, workspaceID, in.ClusterID, hash, at, snapshotID, hostID, changed)
	return res, err
}
