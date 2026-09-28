import { cache } from "react";

import { pool } from "./db";
import type { ImageScore } from "./image-score";
import {
  IMAGE_SCORE_COLUMNS,
  type ImageScoreDbRow,
  mapImageScore,
  RELEASE_JOIN,
} from "./queries-image-scores";
import type { CollectorStatus } from "./queries-inventory";
import { isUuid } from "./queries-inventory";

// Host-level Docker inventory (migration 0013, DOMAIN_MODEL.md §4.5
// "Docker", PROTOCOL.md "Docker sections"): containers and images as
// validity ranges (open range = current), the engine / Swarm membership as
// current per-host state. Every query is scoped by hosts.user_id; callers
// pass the userId from requireHost(). Fleet-wide Docker queries live in
// queries-docker-fleet.ts.

// ---------------------------------------------------------------------------
// Collection state (the empty-state reason)
// ---------------------------------------------------------------------------

// Why a Docker tab shows what it shows, from the newest snapshot's
// collector_status. Stored rows stay as last known when collection stops,
// so pages check this before trusting "no rows" or showing rows as current.
export type DockerCollection =
  // Remote (SSH) target: read-only SFTP can't reach the socket.
  | { kind: "remote" }
  // Local agent without the socket mounted (opt-in).
  | { kind: "not_enabled" }
  // Something at the socket, but unusable; error is docker_engine's text.
  | { kind: "engine_unavailable"; error: string | null }
  // The collector itself failed (time budget ran out, agent stopping).
  | { kind: "error"; error: string | null }
  // No status at all: no snapshot yet, or an agent build without the
  // Docker collectors. Not authoritative (PROTOCOL.md), so not "not enabled".
  | { kind: "not_reported" }
  // Skipped for a reason this dashboard doesn't know.
  | { kind: "skipped"; reason: string | null }
  | { kind: "ok"; truncated: boolean };

// PROTOCOL.md "Docker sections": exact reason strings.
export const DOCKER_REASON_REMOTE = "remote host";
export const DOCKER_REASON_NO_SOCKET = "docker socket not mounted";
export const DOCKER_REASON_ENGINE = "docker engine unavailable";

export function dockerCollection(
  collectorStatus: Record<string, CollectorStatus> | null | undefined,
  collector: "docker_containers" | "docker_images",
  // Every agent collecting this host reaches it remotely: an older remote
  // agent may not report the Docker collectors at all.
  onlyRemote: boolean,
): DockerCollection {
  const s = collectorStatus?.[collector] as (CollectorStatus & { truncated?: boolean }) | undefined;
  const engine = collectorStatus?.docker_engine;
  if (!s) return onlyRemote ? { kind: "remote" } : { kind: "not_reported" };
  if (s.status === "ok") return { kind: "ok", truncated: s.truncated === true };
  if (s.status === "error") return { kind: "error", error: s.error ?? null };
  if (s.reason === DOCKER_REASON_REMOTE) return { kind: "remote" };
  if (s.reason === DOCKER_REASON_NO_SOCKET) return { kind: "not_enabled" };
  if (s.reason === DOCKER_REASON_ENGINE || engine?.status === "error") {
    return { kind: "engine_unavailable", error: engine?.error ?? null };
  }
  return { kind: "skipped", reason: s.reason ?? null };
}

// When a kind was last confirmed / changed (host_fact_state), or null when
// its collector has never reported ok for this host.
export type DockerFreshness = { confirmedAt: string; changedAt: string } | null;

async function freshness(userId: string, hostId: string, kind: string): Promise<DockerFreshness> {
  const { rows } = await pool.query<{ confirmed_at: Date; changed_at: Date }>(
    `SELECT st.confirmed_at, st.changed_at
     FROM hosts h JOIN host_fact_state st ON st.host_id = h.id
     WHERE h.id = $2 AND h.user_id = $1 AND st.kind = $3`,
    [userId, hostId, kind],
  );
  const r = rows[0];
  return r
    ? { confirmedAt: r.confirmed_at.toISOString(), changedAt: r.changed_at.toISOString() }
    : null;
}

// ---------------------------------------------------------------------------
// Engine / Swarm (host_docker)
// ---------------------------------------------------------------------------

export type HostDockerEngine = {
  engineVersion: string | null;
  apiVersion: string | null;
  storageDriver: string | null;
  imageStore: string | null;
  rootless: boolean | null;
  swarmState: string | null;
  swarmRole: string | null;
  swarmNodeId: string | null;
  swarmClusterId: string | null;
  collectedAt: string | null;
};

export const getHostDockerEngine = cache(async function getHostDockerEngine(
  userId: string,
  hostId: string,
): Promise<HostDockerEngine | null> {
  if (!isUuid(hostId)) return null;
  const { rows } = await pool.query<{
    engine_version: string | null;
    api_version: string | null;
    storage_driver: string | null;
    image_store: string | null;
    rootless: boolean | null;
    swarm_state: string | null;
    swarm_role: string | null;
    swarm_node_id: string | null;
    swarm_cluster_id: string | null;
    engine_collected_at: Date | null;
  }>(
    `SELECT d.engine_version, d.api_version, d.storage_driver, d.image_store, d.rootless,
            d.swarm_state, d.swarm_role, d.swarm_node_id, d.swarm_cluster_id, d.engine_collected_at
     FROM hosts h JOIN host_docker d ON d.host_id = h.id
     WHERE h.id = $2 AND h.user_id = $1`,
    [userId, hostId],
  );
  const r = rows[0];
  if (!r || !r.engine_collected_at) return null;
  return {
    engineVersion: r.engine_version,
    apiVersion: r.api_version,
    storageDriver: r.storage_driver,
    imageStore: r.image_store,
    rootless: r.rootless,
    swarmState: r.swarm_state,
    swarmRole: r.swarm_role,
    swarmNodeId: r.swarm_node_id,
    swarmClusterId: r.swarm_cluster_id,
    collectedAt: r.engine_collected_at.toISOString(),
  };
});

// ---------------------------------------------------------------------------
// Containers
// ---------------------------------------------------------------------------

// migration 0013 host_containers.ports / .mounts.
export type ContainerPort = {
  host_ip?: string;
  host_port?: number;
  container_port: number;
  proto: string;
};
export type ContainerMount = {
  type: string;
  source?: string;
  destination: string;
  rw: boolean;
};

export type HostContainerRow = {
  id: string;
  name: string;
  image: string | null;
  imageId: string | null;
  // Tags / digests of the image actually run, from host_images (empty when
  // the image isn't listed on the host, e.g. removed after the container
  // was created).
  imageTags: string[];
  imageDigests: string[];
  state: string | null;
  startedAt: string | null;
  composeProject: string | null;
  composeService: string | null;
  swarmStack: string | null;
  swarmServiceName: string | null;
  // Detail columns: null = never successfully inspected ("details
  // unavailable"), not empty.
  ports: ContainerPort[] | null;
  networks: string[] | null;
  networkMode: string | null;
  privileged: boolean | null;
  restartPolicy: string | null;
  mounts: ContainerMount[] | null;
  // Set while the last push had only a partial entry for it.
  inspectError: string | null;
  // In this exact state (name, image, state, ports…) since.
  since: string;
  // The image's platform on this host (null = image not listed or not
  // inspected) and its score (image_scores(user)).
  imagePlatform: { os: string; arch: string; variant: string } | null;
  imageScore: ImageScore | null;
};

export async function getHostContainers(userId: string, hostId: string) {
  if (!isUuid(hostId)) return { rows: [] as HostContainerRow[], freshness: null };
  const { rows } = await pool.query<
    ImageScoreDbRow & {
      image_os: string | null;
      image_arch: string | null;
      image_variant: string | null;
      container_id: string;
      name: string;
      image: string | null;
      image_id: string | null;
      repo_tags: string[] | null;
      repo_digests: string[] | null;
      state: string | null;
      started_at: Date | null;
      compose_project: string | null;
      compose_service: string | null;
      swarm_stack: string | null;
      swarm_service_name: string | null;
      ports: ContainerPort[] | null;
      networks: string[] | null;
      network_mode: string | null;
      privileged: boolean | null;
      restart_policy: string | null;
      mounts: ContainerMount[] | null;
      inspect_error: string | null;
      first_seen_at: Date;
    }
  >(
    `SELECT c.container_id, c.name, c.image, c.image_id, i.repo_tags, i.repo_digests,
            c.state, c.started_at, c.compose_project, c.compose_service, c.swarm_stack,
            c.swarm_service_name, c.ports, c.networks, c.network_mode, c.privileged,
            c.restart_policy, c.mounts, c.inspect_error, c.first_seen_at,
            i.os AS image_os, i.arch AS image_arch, i.variant AS image_variant,
            ${IMAGE_SCORE_COLUMNS}
     FROM hosts h
     JOIN host_containers c ON c.host_id = h.id AND c.removed_at IS NULL
     LEFT JOIN host_images i
       ON i.host_id = h.id AND i.image_id = c.image_id AND i.removed_at IS NULL
     LEFT JOIN image_scores($1) s
       ON s.image_id = i.image_id AND s.os = i.os AND s.arch = i.arch AND s.variant = i.variant
     ${RELEASE_JOIN}
     WHERE h.id = $2 AND h.user_id = $1
     ORDER BY c.name`,
    [userId, hostId],
  );
  return {
    rows: rows.map((r): HostContainerRow => ({
      id: r.container_id,
      name: r.name,
      image: r.image,
      imageId: r.image_id,
      imageTags: r.repo_tags ?? [],
      imageDigests: r.repo_digests ?? [],
      state: r.state,
      startedAt: r.started_at?.toISOString() ?? null,
      composeProject: r.compose_project,
      composeService: r.compose_service,
      swarmStack: r.swarm_stack,
      swarmServiceName: r.swarm_service_name,
      ports: r.ports,
      networks: r.networks,
      networkMode: r.network_mode,
      privileged: r.privileged,
      restartPolicy: r.restart_policy,
      mounts: r.mounts,
      inspectError: r.inspect_error,
      since: r.first_seen_at.toISOString(),
      imagePlatform:
        r.image_os !== null && r.image_arch !== null && r.image_variant !== null
          ? { os: r.image_os, arch: r.image_arch, variant: r.image_variant }
          : null,
      imageScore: mapImageScore(r),
    })),
    freshness: await freshness(userId, hostId, "containers:docker"),
  };
}

// ---------------------------------------------------------------------------
// Images
// ---------------------------------------------------------------------------

export type HostImageRow = {
  imageId: string;
  repoTags: string[];
  repoDigests: string[];
  // Platform: null = never inspected on this host.
  os: string | null;
  arch: string | null;
  variant: string | null;
  // From container_images (only once inspected).
  created: string | null;
  inspectError: string | null;
  // Open host_containers running this image id (any state) / running.
  containers: number;
  running: number;
  since: string;
  // image_scores(user) for the image key; null until inspected.
  score: ImageScore | null;
};

export async function getHostImages(userId: string, hostId: string) {
  if (!isUuid(hostId)) return { rows: [] as HostImageRow[], freshness: null };
  const { rows } = await pool.query<
    ImageScoreDbRow & {
      image_id: string;
      repo_tags: string[];
      repo_digests: string[];
      os: string | null;
      arch: string | null;
      variant: string | null;
      created: Date | null;
      inspect_error: string | null;
      containers: string;
      running: string;
      first_seen_at: Date;
    }
  >(
    `SELECT i.image_id, i.repo_tags, i.repo_digests, i.os, i.arch, i.variant, ci.created,
            i.inspect_error, coalesce(u.containers, 0) AS containers,
            coalesce(u.running, 0) AS running, i.first_seen_at, ${IMAGE_SCORE_COLUMNS}
     FROM hosts h
     JOIN host_images i ON i.host_id = h.id AND i.removed_at IS NULL
     -- = USING (image_id, os, arch, variant); spelled out because hosts
     -- has an arch column too. Matches only once inspected on this host.
     LEFT JOIN container_images ci
       ON ci.image_id = i.image_id AND ci.os = i.os AND ci.arch = i.arch
      AND ci.variant = i.variant
     LEFT JOIN image_scores($1) s
       ON s.image_id = i.image_id AND s.os = i.os AND s.arch = i.arch AND s.variant = i.variant
     ${RELEASE_JOIN}
     LEFT JOIN (
       SELECT c.image_id, count(*) AS containers,
              count(*) FILTER (WHERE c.state = 'running') AS running
       FROM host_containers c
       WHERE c.host_id = $2 AND c.removed_at IS NULL
       GROUP BY c.image_id
     ) u ON u.image_id = i.image_id
     WHERE h.id = $2 AND h.user_id = $1
     ORDER BY (i.repo_tags = '{}'), i.repo_tags[1], i.image_id`,
    [userId, hostId],
  );
  return {
    rows: rows.map((r): HostImageRow => ({
      imageId: r.image_id,
      repoTags: r.repo_tags,
      repoDigests: r.repo_digests,
      os: r.os,
      arch: r.arch,
      variant: r.variant,
      created: r.created?.toISOString() ?? null,
      inspectError: r.inspect_error,
      containers: Number(r.containers),
      running: Number(r.running),
      since: r.first_seen_at.toISOString(),
      score: mapImageScore(r),
    })),
    freshness: await freshness(userId, hostId, "images:docker"),
  };
}

// ---------------------------------------------------------------------------
// History: container / image range opens and closes
// ---------------------------------------------------------------------------

const utcKey = (col: string) =>
  `to_char(${col} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;

export type DockerRangeEvent = {
  kind: "open" | "close";
  at: string; // exact UTC boundary, same format as RangeEvent.at
  // 'containers:docker' | 'images:docker'
  factKind: "containers:docker" | "images:docker";
  key: string; // container id / image id
  name: string; // container name / first repo tag (or short id)
  // Containers.
  image: string | null;
  imageId: string | null;
  state: string | null;
  ports: ContainerPort[] | null;
  networks: string[] | null;
  restartPolicy: string | null;
  privileged: boolean | null;
  mounts: ContainerMount[] | null;
  // Images.
  repoTags: string[];
};

export type DockerHistory = {
  // Newest first, at most `limit`, older than the cursor.
  boundaries: {
    at: string;
    events: DockerRangeEvent[];
    // Kinds whose first-ever list was recorded at this boundary (every
    // event of that kind here is an open of the baseline).
    baselineKinds: DockerRangeEvent["factKind"][];
  }[];
  // True when older boundaries exist beyond this page.
  more: boolean;
};

// Same shape as getHostHistory (packages): the newest `limit` boundaries
// older than `before`, then every open/close within them. The History page
// merges the two timelines.
export async function getHostDockerHistory(
  userId: string,
  hostId: string,
  opts: { before: string | null; limit: number },
): Promise<DockerHistory> {
  if (!isUuid(hostId)) return { boundaries: [], more: false };
  const b = await pool.query<{ at: string }>(
    `WITH owned AS (SELECT id FROM hosts WHERE id = $2 AND user_id = $1)
     SELECT ${utcKey("at")} AS at FROM (
       SELECT c.first_seen_at AS at FROM host_containers c JOIN owned ON c.host_id = owned.id
       WHERE ($3::timestamptz IS NULL OR c.first_seen_at < $3::timestamptz)
       UNION
       SELECT c.removed_at FROM host_containers c JOIN owned ON c.host_id = owned.id
       WHERE c.removed_at IS NOT NULL AND ($3::timestamptz IS NULL OR c.removed_at < $3::timestamptz)
       UNION
       SELECT i.first_seen_at FROM host_images i JOIN owned ON i.host_id = owned.id
       WHERE ($3::timestamptz IS NULL OR i.first_seen_at < $3::timestamptz)
       UNION
       SELECT i.removed_at FROM host_images i JOIN owned ON i.host_id = owned.id
       WHERE i.removed_at IS NOT NULL AND ($3::timestamptz IS NULL OR i.removed_at < $3::timestamptz)
     ) b
     ORDER BY at DESC
     LIMIT $4`,
    [userId, hostId, opts.before, opts.limit + 1],
  );
  const all = b.rows.map((r) => r.at);
  const page = all.slice(0, opts.limit);
  if (page.length === 0) return { boundaries: [], more: false };
  const newest = page[0];
  const oldest = page[page.length - 1];

  const ev = await pool.query<{
    kind: "open" | "close";
    fact_kind: DockerRangeEvent["factKind"];
    at: string;
    key: string;
    name: string;
    image: string | null;
    image_id: string | null;
    state: string | null;
    ports: ContainerPort[] | null;
    networks: string[] | null;
    restart_policy: string | null;
    privileged: boolean | null;
    mounts: ContainerMount[] | null;
    repo_tags: string[] | null;
  }>(
    `WITH owned AS (SELECT id FROM hosts WHERE id = $2 AND user_id = $1),
     c AS (
       SELECT c.* FROM host_containers c JOIN owned ON c.host_id = owned.id
       WHERE c.first_seen_at BETWEEN $3::timestamptz AND $4::timestamptz
          OR c.removed_at BETWEEN $3::timestamptz AND $4::timestamptz
     ),
     i AS (
       SELECT i.* FROM host_images i JOIN owned ON i.host_id = owned.id
       WHERE i.first_seen_at BETWEEN $3::timestamptz AND $4::timestamptz
          OR i.removed_at BETWEEN $3::timestamptz AND $4::timestamptz
     )
     SELECT e.kind, 'containers:docker' AS fact_kind, ${utcKey("e.at")} AS at,
            c.container_id AS key, c.name, c.image, c.image_id, c.state, c.ports, c.networks,
            c.restart_policy, c.privileged, c.mounts, NULL::text[] AS repo_tags
     FROM c CROSS JOIN LATERAL (VALUES ('open', c.first_seen_at), ('close', c.removed_at)) e(kind, at)
     WHERE e.at BETWEEN $3::timestamptz AND $4::timestamptz
     UNION ALL
     SELECT e.kind, 'images:docker', ${utcKey("e.at")}, i.image_id,
            coalesce(i.repo_tags[1], i.image_id), NULL, i.image_id, NULL, NULL, NULL,
            NULL, NULL, NULL, i.repo_tags
     FROM i CROSS JOIN LATERAL (VALUES ('open', i.first_seen_at), ('close', i.removed_at)) e(kind, at)
     WHERE e.at BETWEEN $3::timestamptz AND $4::timestamptz
     ORDER BY at DESC, fact_kind, name, kind DESC`,
    [userId, hostId, oldest, newest],
  );
  const firsts = await pool.query<{ kind: DockerRangeEvent["factKind"]; first_at: string }>(
    `SELECT 'containers:docker' AS kind, ${utcKey("min(c.first_seen_at)")} AS first_at
     FROM hosts h JOIN host_containers c ON c.host_id = h.id
     WHERE h.id = $2 AND h.user_id = $1
     UNION ALL
     SELECT 'images:docker', ${utcKey("min(i.first_seen_at)")}
     FROM hosts h JOIN host_images i ON i.host_id = h.id
     WHERE h.id = $2 AND h.user_id = $1`,
    [userId, hostId],
  );

  const byAt = new Map<string, DockerRangeEvent[]>();
  for (const at of page) byAt.set(at, []);
  for (const e of ev.rows) {
    byAt.get(e.at)?.push({
      kind: e.kind,
      at: e.at,
      factKind: e.fact_kind,
      key: e.key,
      name: e.name,
      image: e.image,
      imageId: e.image_id,
      state: e.state,
      ports: e.ports,
      networks: e.networks,
      restartPolicy: e.restart_policy,
      privileged: e.privileged,
      mounts: e.mounts,
      repoTags: e.repo_tags ?? [],
    });
  }
  return {
    boundaries: page.map((at) => ({
      at,
      events: byAt.get(at) ?? [],
      baselineKinds: firsts.rows.filter((f) => f.first_at === at).map((f) => f.kind),
    })),
    more: all.length > opts.limit,
  };
}
