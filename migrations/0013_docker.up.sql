-- P1.6 Docker inventory (TASKS.md Phase 1.6, PROTOCOL.md "Docker
-- sections"): containers and images as validity ranges on the 0010
-- pattern, images interned fleet-wide, Swarm services per cluster, and the
-- engine / Swarm membership / networks as current per-host state.
--
-- Range tables here extend 0010's with two optional columns (see
-- server/internal/hostfacts "Detail" / "Live"):
--   detail_hash  hash of the columns an inspect provides. A container or
--                image whose inspect failed (payload inspect_error) is a
--                partial entry: those columns are unknown, not empty, so
--                the range keeps (or, if the list fields changed, the new
--                range copies) the previous range's values and detail_hash
--                instead of overwriting them with NULLs. NULL detail
--                columns therefore mean "never successfully inspected".
--   live_hash    hash of the live columns: stored on the range, updated in
--                place, never part of row_hash, so they don't open ranges.
-- Point-in-time T: first_seen_at <= T AND (removed_at IS NULL OR removed_at > T).
-- Current rows: removed_at IS NULL. Every kind is diffed only when its
-- collector reported ok; truncated = additive only (host_fact_state).
--
-- No backfill: nothing earlier stored Docker data.

BEGIN;

-- Image content, interned fleet-wide. Keyed by (image_id, os, arch,
-- variant), not image_id alone: on the classic (graphdriver) store the
-- image id is the config digest and fixes the platform, but on the
-- containerd image store it is the digest of the image index (a
-- multi-platform manifest list), so two hosts of different architectures
-- report the same id with different platforms and layers. Rows are
-- immutable once written (ON CONFLICT DO NOTHING). Only fully inspected
-- images are interned: a partial entry has no platform.
CREATE TABLE container_images (
    image_id      text NOT NULL,                -- 'sha256:…'
    os            text NOT NULL,                -- '' when the engine reports none
    arch          text NOT NULL,
    variant       text NOT NULL DEFAULT '',     -- 'v7', 'v8'; '' when none
    created       timestamptz,
    layers        text[] NOT NULL DEFAULT '{}', -- RootFS diff IDs, base first
    labels        jsonb NOT NULL DEFAULT '{}',  -- org.opencontainers.image.* (agent allowlist)
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (image_id, os, arch, variant)
);

-- An image present on a host (kind 'images:docker'). row_key = image_id.
-- row_hash covers the repo tags / digests (re-tagging opens a new range)
-- and detail_hash (the platform). Join to content with
--   JOIN container_images ci USING (image_id, os, arch, variant)
-- which only matches once the image was inspected on this host.
CREATE TABLE host_images (
    host_id                uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    image_id               text NOT NULL,
    repo_tags              text[] NOT NULL DEFAULT '{}',
    repo_digests           text[] NOT NULL DEFAULT '{}',
    -- Detail (from inspect; NULL = never inspected on this host).
    os                     text,
    arch                   text,
    variant                text,
    -- Live.
    inspect_error          text,               -- set while the last push had a partial entry
    row_key                text NOT NULL,
    row_hash               text NOT NULL,
    detail_hash            text NOT NULL,
    live_hash              text NOT NULL,
    first_seen_at          timestamptz NOT NULL,
    first_seen_snapshot_id uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    removed_at             timestamptz,
    removed_snapshot_id    uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    PRIMARY KEY (host_id, row_key, first_seen_at),
    CONSTRAINT host_images_range_ck CHECK (removed_at IS NULL OR removed_at > first_seen_at),
    CONSTRAINT host_images_content_fk FOREIGN KEY (image_id, os, arch, variant)
        REFERENCES container_images (image_id, os, arch, variant)
);
CREATE UNIQUE INDEX host_images_open_uq ON host_images (host_id, row_key) WHERE removed_at IS NULL;
-- Fleet images page: "which hosts have image X".
CREATE INDEX host_images_image_open_idx ON host_images (image_id) WHERE removed_at IS NULL;
CREATE INDEX host_images_digests_open_idx ON host_images USING gin (repo_digests) WHERE removed_at IS NULL;

-- A container on a host, running or not (kind 'containers:docker').
-- row_key = container_id (a recreated container is a new id, so a new
-- range anyway).
--
-- What opens a new range: any change to the hashed columns, including
-- state. This mirrors host_services, where a unit going running ->
-- stopped closes its range and opens a new one: "db stopped at 10:02" is
-- history the dashboard can show, and exposure needs it (a stopped
-- container publishes nothing). Changes are sampled per push, so a crash
-- loop costs at most one range per push, as for services.
-- What updates in place (live): started_at, so a restart that ends in the
-- same state (restart policy, `docker restart` between two pushes) is not
-- a range of its own; and inspect_error.
CREATE TABLE host_containers (
    host_id                uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    container_id           text NOT NULL,       -- full 64-hex id
    name                   text NOT NULL,
    image                  text,                -- reference as configured (Config.Image)
    image_id               text,                -- image actually run; join host_images on (host_id, image_id)
    state                  text,                -- created | running | paused | restarting | removing | exited | dead
    -- Pulled out of labels (the agent's allowlist) for grouping.
    compose_project        text,                -- com.docker.compose.project
    compose_service        text,                -- com.docker.compose.service
    swarm_stack            text,                -- com.docker.stack.namespace
    swarm_service_id       text,                -- com.docker.swarm.service.id (join swarm_services.service_id)
    swarm_service_name     text,                -- com.docker.swarm.service.name
    swarm_task_id          text,                -- com.docker.swarm.task.id
    labels                 jsonb NOT NULL DEFAULT '{}',
    -- Detail (from inspect; NULL = unknown, never inspected).
    ports                  jsonb,               -- [{host_ip?, host_port?, container_port, proto}], [] = none published
    networks               text[],
    network_mode           text,                -- bridge | host | none | container:<id> | <network name>
    privileged             boolean,
    restart_policy         text,
    mounts                 jsonb,               -- [{type, source? (bind only: host path), destination, rw}]
    -- Live.
    started_at             timestamptz,         -- last start; NULL = never started (or unknown)
    inspect_error          text,
    row_key                text NOT NULL,
    row_hash               text NOT NULL,
    detail_hash            text NOT NULL,
    live_hash              text NOT NULL,
    first_seen_at          timestamptz NOT NULL,
    first_seen_snapshot_id uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    removed_at             timestamptz,
    removed_snapshot_id    uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    PRIMARY KEY (host_id, row_key, first_seen_at),
    CONSTRAINT host_containers_range_ck CHECK (removed_at IS NULL OR removed_at > first_seen_at)
);
CREATE UNIQUE INDEX host_containers_open_uq ON host_containers (host_id, row_key) WHERE removed_at IS NULL;
CREATE INDEX host_containers_image_open_idx ON host_containers (image_id) WHERE removed_at IS NULL;
CREATE INDEX host_containers_swarm_service_open_idx ON host_containers (swarm_service_id)
    WHERE removed_at IS NULL AND swarm_service_id IS NOT NULL;

-- Current Docker state per host that isn't worth a range table: the
-- engine and Swarm membership (collector docker_engine) and the networks
-- (collector docker_networks). Each part is written only from a push
-- whose collector for it was ok and that is newer than the part's
-- *_collected_at, and is otherwise left as last known: when Docker
-- collection stops (socket unmounted), the row keeps its last values and
-- the dashboard takes the empty-state reason from the newest snapshot's
-- collector_status.
--
-- Networks are not a range table: nothing in the plan alerts on or keys
-- off a network's history (exposure needs container ports and
-- network_mode, which are on host_containers), and a network is only
-- displayed next to the containers attached to it by name. Promote them
-- if that changes.
CREATE TABLE host_docker (
    host_id               uuid PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    engine_version        text,
    api_version           text,                -- engine's highest supported API version
    storage_driver        text,
    image_store           text,                -- 'containerd' | 'graphdriver' | NULL (unknown, e.g. Podman)
    rootless              boolean,
    -- Swarm membership; all NULL when the node isn't in a Swarm. While a
    -- manager is locked (swarm_state 'locked') the engine reports no
    -- node/cluster/role, so the previous values are kept.
    swarm_state           text,                -- 'active' | 'locked'
    swarm_node_id         text,
    swarm_cluster_id      text,                -- managers only: workers are never told it
    swarm_role            text,                -- 'manager' | 'worker'
    engine_collected_at   timestamptz,
    engine_snapshot_id    uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    networks              jsonb,               -- [{id, name, driver, scope, internal, subnets}]
    networks_truncated    boolean NOT NULL DEFAULT false,
    networks_collected_at timestamptz,
    networks_snapshot_id  uuid REFERENCES snapshots(id) ON DELETE SET NULL
);
CREATE INDEX host_docker_cluster_idx ON host_docker (swarm_cluster_id) WHERE swarm_cluster_id IS NOT NULL;

-- A Swarm cluster as seen by one user's managers, and the bookkeeping for
-- its services (the host_fact_state of a cluster). Keyed by user as well:
-- cluster_id comes from an agent, and one user's agent must not be able to
-- write another user's cluster.
CREATE TABLE swarm_clusters (
    user_id               uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    cluster_id            text NOT NULL,
    set_hash              text,                -- NULL after a truncated push
    confirmed_at          timestamptz NOT NULL,
    confirmed_snapshot_id uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    changed_at            timestamptz NOT NULL,
    first_seen_at         timestamptz NOT NULL,
    last_manager_host_id  uuid REFERENCES hosts(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, cluster_id)
);

-- Swarm services per cluster, from any manager's ok push. row_key =
-- service_id. The spec (name, image, mode, replicas, labels, ports) is
-- hashed: a service update (new image, scaled) opens a new range.
-- running_tasks / desired_tasks are live (current values, updated in
-- place). A service missing from an ok, non-truncated push by any manager
-- of the cluster is closed.
CREATE TABLE swarm_services (
    user_id                uuid NOT NULL,
    cluster_id             text NOT NULL,
    service_id             text NOT NULL,
    name                   text NOT NULL,
    image                  text,                -- NULL for plugin services
    mode                   text,                -- replicated | global | replicated-job | global-job
    replicas               int,                 -- replicated only
    swarm_stack            text,                -- com.docker.stack.namespace
    labels                 jsonb NOT NULL DEFAULT '{}',
    ports                  jsonb NOT NULL DEFAULT '[]', -- [{published?, target, proto, publish_mode}]
    running_tasks          int,                 -- live; NULL = engine didn't report
    desired_tasks          int,                 -- live
    row_key                text NOT NULL,
    row_hash               text NOT NULL,
    live_hash              text NOT NULL,
    first_seen_at          timestamptz NOT NULL,
    first_seen_snapshot_id uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    removed_at             timestamptz,
    removed_snapshot_id    uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, cluster_id, row_key, first_seen_at),
    FOREIGN KEY (user_id, cluster_id) REFERENCES swarm_clusters (user_id, cluster_id) ON DELETE CASCADE,
    CONSTRAINT swarm_services_range_ck CHECK (removed_at IS NULL OR removed_at > first_seen_at)
);
CREATE UNIQUE INDEX swarm_services_open_uq ON swarm_services (user_id, cluster_id, row_key) WHERE removed_at IS NULL;

COMMIT;
