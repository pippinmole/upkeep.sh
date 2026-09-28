import { cache } from "react";

import { pool } from "./db";
import type { ImageKey } from "./image-key";
import type { ImageScore } from "./image-score";
import {
  IMAGE_SCORE_COLUMNS,
  type ImageScoreDbRow,
  mapImageScore,
  RELEASE_JOIN,
} from "./queries-image-scores";

// Fleet-level Docker reads (docs/tasks/phase-1-6-docker-exposure.md; migration 0013,
// DOMAIN_MODEL.md §4.5 "Docker"): the fleet Images page and the Swarm
// cluster view. Per-host Containers / Images tabs live in queries-docker.ts.
//
// Tenancy: container_images is interned fleet-wide ACROSS USERS, and
// swarm cluster / service ids come from agents. Every query here starts
// from the user's own rows: `hosts h WHERE h.user_id = $1` for
// host_images / host_containers / host_docker, and `(user_id, cluster_id)`
// for swarm_clusters / swarm_services. Task containers are only joined to
// services through hosts of the same user. Current rows are
// `removed_at IS NULL`; archived hosts are left out, as on other fleet
// pages.

// ---------------------------------------------------------------------------
// Image references
// ---------------------------------------------------------------------------

// Pseudo-repository for images with neither a tag nor a digest. The
// segment can't be a real repository: Docker path components must start
// with a lowercase letter or digit.
export const UNTAGGED_REPO = "_untagged";

// One row per (host image, repository, tag): a repo tag "repo:tag" gives
// its repo and tag; a repo digest "repo@sha256:…" gives its repo with a
// NULL tag, kept only when the image has no tag in that repository (a
// pulled image whose tag moved on); an image with neither is repo ''.
// `digests` are that image's manifest digests within the repository.
// The tag is what follows the last ':' after the last '/', so registry
// ports ("host:5000/app:1") stay in the repository.
const REFS_CTE = `
imgs AS (
  SELECT hi.host_id, hi.image_id, hi.repo_tags, hi.repo_digests, hi.os, hi.arch, hi.variant,
         concat_ws('/', nullif(hi.os, ''), nullif(hi.arch, ''), nullif(hi.variant, '')) AS platform
  FROM hosts h
  JOIN host_images hi ON hi.host_id = h.id AND hi.removed_at IS NULL
  WHERE h.user_id = $1 AND h.archived_at IS NULL
),
refs AS (
  SELECT i.host_id, i.image_id, i.os, i.arch, i.variant, i.platform, r.repo, r.tag,
         ARRAY(SELECT split_part(d, '@', 2) FROM unnest(i.repo_digests) d
               WHERE split_part(d, '@', 1) = r.repo) AS digests
  FROM imgs i
  CROSS JOIN LATERAL (
    SELECT DISTINCT x.repo, x.tag
    FROM (
      SELECT x0.*, bool_or(x0.tag IS NOT NULL) OVER (PARTITION BY x0.repo) AS repo_tagged
      FROM (
        SELECT regexp_replace(t, ':[^:/]+$', '') AS repo,
               substring(t FROM ':([^:/]+)$') AS tag
        FROM unnest(i.repo_tags) t WHERE t <> '<none>:<none>'
        UNION ALL
        SELECT split_part(d, '@', 1), NULL
        FROM unnest(i.repo_digests) d WHERE d <> '<none>@<none>'
        UNION ALL
        SELECT '', NULL
        WHERE NOT EXISTS (SELECT 1 FROM unnest(i.repo_tags) t WHERE t <> '<none>:<none>')
          AND NOT EXISTS (SELECT 1 FROM unnest(i.repo_digests) d WHERE d <> '<none>@<none>')
      ) x0
    ) x
    WHERE x.tag IS NOT NULL OR NOT x.repo_tagged
  ) r
)`;

export type FleetImageTag = {
  tag: string | null; // null = digest only (no tag in this repository)
  hosts: number;
  imageIds: number;
  platforms: number;
  digests: number;
};

export type FleetImageRow = {
  repo: string; // '' = untagged images
  hosts: number;
  imageIds: number;
  runningContainers: number;
  tags: FleetImageTag[];
};

// "Same tag, different content across hosts": more than one manifest
// digest for the tag, or more image ids than platforms (one platform
// should map to one image id; different architectures legitimately have
// different ids on the classic image store).
export function tagDrifts(t: Pick<FleetImageTag, "digests" | "imageIds" | "platforms">): boolean {
  return t.digests > 1 || t.imageIds > Math.max(1, t.platforms);
}

export async function getFleetImages(
  userId: string,
  f: {
    q: string | null;
    sort: "name" | "hosts";
    page: number;
    pageSize: number;
  },
): Promise<{ rows: FleetImageRow[]; total: number }> {
  const orderBy = f.sort === "hosts" ? "p.repo = '', p.hosts DESC, p.repo" : "p.repo = '', p.repo";
  const { rows } = await pool.query<{
    repo: string;
    hosts: string;
    image_ids: string;
    running: string;
    tags: FleetImageTag[];
    total: string;
  }>(
    `WITH ${REFS_CTE},
     matched AS (
       SELECT DISTINCT repo FROM refs
       WHERE $2::text IS NULL
          OR strpos(lower(repo), lower($2)) > 0
          OR strpos(lower(coalesce(tag, '')), lower($2)) > 0
          OR strpos(image_id, lower($2)) > 0
          OR EXISTS (SELECT 1 FROM unnest(digests) d WHERE strpos(d, lower($2)) > 0)
     ),
     tags AS (
       SELECT r.repo, r.tag,
              count(DISTINCT r.host_id) AS hosts,
              count(DISTINCT r.image_id) AS image_ids,
              count(DISTINCT r.platform) AS platforms,
              count(DISTINCT d) AS digests
       FROM refs r
       JOIN matched m USING (repo)
       LEFT JOIN LATERAL unnest(r.digests) d ON true
       GROUP BY r.repo, r.tag
     ),
     running AS (
       SELECT r.repo, count(DISTINCT (c.host_id, c.container_id)) AS n
       FROM (SELECT DISTINCT repo, host_id, image_id FROM refs JOIN matched USING (repo)) r
       JOIN host_containers c
         ON c.host_id = r.host_id AND c.image_id = r.image_id
        AND c.removed_at IS NULL AND c.state = 'running'
       GROUP BY r.repo
     ),
     repos AS (
       SELECT r.repo, count(DISTINCT r.host_id) AS hosts, count(DISTINCT r.image_id) AS image_ids
       FROM refs r JOIN matched USING (repo)
       GROUP BY r.repo
     )
     SELECT p.repo, p.hosts, p.image_ids, coalesce(ru.n, 0) AS running,
            (SELECT json_agg(json_build_object(
                      'tag', t.tag, 'hosts', t.hosts, 'imageIds', t.image_ids,
                      'platforms', t.platforms, 'digests', t.digests)
                    ORDER BY t.tag NULLS LAST)
             FROM tags t WHERE t.repo = p.repo) AS tags,
            count(*) OVER () AS total
     FROM repos p
     LEFT JOIN running ru USING (repo)
     ORDER BY ${orderBy}
     LIMIT $3 OFFSET $4`,
    [userId, f.q, f.pageSize, (f.page - 1) * f.pageSize],
  );
  return {
    rows: rows.map((r) => ({
      repo: r.repo,
      hosts: Number(r.hosts),
      imageIds: Number(r.image_ids),
      runningContainers: Number(r.running),
      tags: r.tags ?? [],
    })),
    total: rows[0] ? Number(rows[0].total) : 0,
  };
}

// The most urgent image of each repository (image_scores(user), highest
// top severity key, then most vulnerabilities) and how many inspected image
// keys the repository has: the fleet Images page's score column.
export type RepoScore = {
  key: ImageKey;
  keys: number;
  hasRepoDigest: boolean;
  score: ImageScore | null;
};

export async function getRepoScores(
  userId: string,
  repos: string[],
): Promise<Map<string, RepoScore>> {
  if (repos.length === 0) return new Map();
  const { rows } = await pool.query<
    ImageScoreDbRow & {
      repo: string;
      image_id: string;
      os: string;
      arch: string;
      variant: string;
      keys: string;
      has_digest: boolean;
    }
  >(
    `WITH ${REFS_CTE},
     k AS (
       SELECT r.repo, r.image_id, r.os, r.arch, r.variant,
              bool_or(cardinality(r.digests) > 0) AS has_digest
       FROM refs r
       WHERE r.repo = ANY($2) AND r.os IS NOT NULL
       GROUP BY 1, 2, 3, 4, 5
     )
     SELECT DISTINCT ON (k.repo) k.repo, k.image_id, k.os, k.arch, k.variant, k.has_digest,
            count(*) OVER (PARTITION BY k.repo) AS keys, ${IMAGE_SCORE_COLUMNS}
     FROM k
     LEFT JOIN image_scores($1) s
       ON s.image_id = k.image_id AND s.os = k.os AND s.arch = k.arch AND s.variant = k.variant
     ${RELEASE_JOIN}
     ORDER BY k.repo, s.top_severity_key DESC NULLS LAST, s.vuln_count DESC NULLS LAST,
              s.list_status = 'ok' DESC, k.image_id`,
    [userId, repos],
  );
  return new Map(
    rows.map((r) => [
      r.repo,
      {
        key: { imageId: r.image_id, os: r.os, arch: r.arch, variant: r.variant },
        keys: Number(r.keys),
        hasRepoDigest: r.has_digest,
        score: mapImageScore(r),
      },
    ]),
  );
}

// ---------------------------------------------------------------------------
// One repository: which hosts have it
// ---------------------------------------------------------------------------

export type ImageContainer = {
  id: string;
  name: string;
  state: string | null;
  image: string | null; // reference as configured
  startedAt: string | null;
  composeProject: string | null;
  swarmServiceName: string | null;
};

export type RepoHostImage = {
  hostId: string;
  hostname: string;
  label: string | null;
  imageId: string;
  platform: string; // '' = never inspected on this host
  // The image key's platform; null = never inspected on this host.
  key: ImageKey | null;
  tags: string[]; // tags in this repository on this host
  digests: string[]; // manifest digests in this repository
  otherRefs: string[]; // tags from other repositories on the same image
  firstSeenAt: string;
  inspectError: string | null;
  containers: ImageContainer[];
};

// Every current host image that belongs to `repo` (UNTAGGED_REPO = images
// with no tag and no digest). Filtering by tag / digest / image id is left
// to the caller so the per-tag summary can be built from the same rows.
export async function getRepoImages(userId: string, repo: string): Promise<RepoHostImage[]> {
  const repoKey = repo === UNTAGGED_REPO ? "" : repo;
  const { rows } = await pool.query<{
    host_id: string;
    hostname: string;
    label: string | null;
    image_id: string;
    platform: string;
    os: string | null;
    arch: string | null;
    variant: string | null;
    tags: string[];
    digests: string[];
    other_refs: string[];
    first_seen_at: Date;
    inspect_error: string | null;
    containers: ImageContainer[];
  }>(
    `WITH ${REFS_CTE},
     mine AS (SELECT DISTINCT host_id, image_id FROM refs WHERE repo = $2)
     SELECT h.id AS host_id, h.hostname, h.label, hi.image_id,
            concat_ws('/', nullif(hi.os, ''), nullif(hi.arch, ''), nullif(hi.variant, '')) AS platform,
            hi.os, hi.arch, hi.variant,
            ARRAY(SELECT substring(t FROM ':([^:/]+)$') FROM unnest(hi.repo_tags) t
                  WHERE regexp_replace(t, ':[^:/]+$', '') = $2 ORDER BY 1) AS tags,
            ARRAY(SELECT split_part(d, '@', 2) FROM unnest(hi.repo_digests) d
                  WHERE split_part(d, '@', 1) = $2 ORDER BY 1) AS digests,
            ARRAY(SELECT t FROM unnest(hi.repo_tags) t
                  WHERE regexp_replace(t, ':[^:/]+$', '') <> $2 AND t <> '<none>:<none>'
                  ORDER BY 1) AS other_refs,
            hi.first_seen_at, hi.inspect_error,
            coalesce((
              SELECT json_agg(json_build_object(
                       'id', c.container_id, 'name', c.name, 'state', c.state,
                       'image', c.image, 'startedAt', c.started_at,
                       'composeProject', c.compose_project,
                       'swarmServiceName', c.swarm_service_name)
                     ORDER BY c.state = 'running' DESC, c.name)
              FROM host_containers c
              WHERE c.host_id = hi.host_id AND c.image_id = hi.image_id AND c.removed_at IS NULL
            ), '[]') AS containers
     FROM mine m
     JOIN hosts h ON h.id = m.host_id AND h.user_id = $1
     JOIN host_images hi
       ON hi.host_id = m.host_id AND hi.image_id = m.image_id AND hi.removed_at IS NULL
     ORDER BY lower(coalesce(h.label, h.hostname)), h.id, hi.first_seen_at DESC
     LIMIT 2000`,
    [userId, repoKey],
  );
  return rows.map((r) => ({
    hostId: r.host_id,
    hostname: r.hostname,
    label: r.label,
    imageId: r.image_id,
    platform: r.platform,
    key:
      r.os !== null && r.arch !== null && r.variant !== null
        ? { imageId: r.image_id, os: r.os, arch: r.arch, variant: r.variant }
        : null,
    tags: r.tags,
    digests: r.digests,
    otherRefs: r.other_refs,
    firstSeenAt: r.first_seen_at.toISOString(),
    inspectError: r.inspect_error,
    containers: r.containers,
  }));
}

// ---------------------------------------------------------------------------
// Coverage: which hosts report Docker, and why the others don't
// ---------------------------------------------------------------------------

export type DockerCoverage = {
  hosts: number; // non-archived hosts
  reporting: number; // docker_images ok in the newest snapshot
  // Hosts not reporting, by cause. `reason` is the collector's exact
  // reason string (PROTOCOL.md "Docker sections") for skipped, the error
  // text's absence for error; `status` 'missing' = the newest snapshot has
  // no docker_images status (agent build without Docker collectors, or no
  // snapshot yet).
  missing: { status: string; reason: string | null; hosts: number }[];
};

export const getDockerCoverage = cache(async function getDockerCoverage(
  userId: string,
): Promise<DockerCoverage> {
  const { rows } = await pool.query<{
    status: string;
    reason: string | null;
    hosts: string;
  }>(
    `SELECT coalesce(s.collector_status->'docker_images'->>'status', 'missing') AS status,
            s.collector_status->'docker_images'->>'reason' AS reason,
            count(*) AS hosts
     FROM hosts h
     LEFT JOIN LATERAL (
       SELECT s.collector_status FROM snapshots s
       WHERE s.host_id = h.id
       ORDER BY s.received_at DESC   -- snapshots_host_id_received_at_idx
       LIMIT 1
     ) s ON true
     WHERE h.user_id = $1 AND h.archived_at IS NULL
     GROUP BY 1, 2
     ORDER BY 3 DESC`,
    [userId],
  );
  let hosts = 0;
  let reporting = 0;
  const missing: DockerCoverage["missing"] = [];
  for (const r of rows) {
    const n = Number(r.hosts);
    hosts += n;
    if (r.status === "ok") reporting += n;
    else missing.push({ status: r.status, reason: r.reason, hosts: n });
  }
  return { hosts, reporting, missing };
});

// ---------------------------------------------------------------------------
// Swarm
// ---------------------------------------------------------------------------

const CLUSTER_ID_RE = /^[A-Za-z0-9]{1,64}$/;

export function isClusterId(s: string): boolean {
  return CLUSTER_ID_RE.test(s);
}

// Whether to show the Swarm nav item: a cluster with services reported,
// or any of the user's hosts being a Swarm member (a worker, or a manager
// whose service list hasn't come in yet).
export const hasSwarm = cache(async function hasSwarm(userId: string): Promise<boolean> {
  const { rows } = await pool.query<{ any: boolean }>(
    `SELECT EXISTS (SELECT 1 FROM swarm_clusters sc WHERE sc.user_id = $1)
         OR EXISTS (SELECT 1 FROM hosts h
                    JOIN host_docker hd ON hd.host_id = h.id
                    WHERE h.user_id = $1 AND h.archived_at IS NULL
                      AND hd.swarm_state IS NOT NULL) AS any`,
    [userId],
  );
  return rows[0]?.any ?? false;
});

type HostRef = { hostId: string; hostname: string; label: string | null };

export type SwarmClusterSummary = {
  clusterId: string;
  // null when no manager's service list has been stored yet (swarm_clusters
  // row missing): the cluster is only known from a manager's engine info.
  firstSeenAt: string | null;
  confirmedAt: string | null;
  lastManager: HostRef | null;
  services: number;
  degraded: number;
  managers: number;
  lockedManagers: number;
  nodes: number; // hosts with an agent known to be in the cluster
};

// Clusters are the user's swarm_clusters plus any cluster id a manager
// host reports (host_docker) before its service list arrived.
const MY_CLUSTERS_CTE = `
my_hosts AS (
  SELECT h.id, h.hostname, h.label FROM hosts h
  WHERE h.user_id = $1 AND h.archived_at IS NULL
),
ids AS (
  SELECT sc.cluster_id FROM swarm_clusters sc WHERE sc.user_id = $1
  UNION
  SELECT hd.swarm_cluster_id FROM host_docker hd
  JOIN my_hosts h ON h.id = hd.host_id
  WHERE hd.swarm_cluster_id IS NOT NULL
),
svc AS (
  SELECT ss.* FROM swarm_services ss
  WHERE ss.user_id = $1 AND ss.removed_at IS NULL
),
tasks AS (
  SELECT svc.cluster_id, svc.service_id, c.host_id, c.container_id, c.state
  FROM svc
  JOIN host_containers c ON c.swarm_service_id = svc.service_id AND c.removed_at IS NULL
  JOIN my_hosts h ON h.id = c.host_id
),
nodes AS (
  SELECT hd.swarm_cluster_id AS cluster_id, hd.host_id FROM host_docker hd
  JOIN my_hosts h ON h.id = hd.host_id
  WHERE hd.swarm_cluster_id IS NOT NULL
  UNION
  SELECT cluster_id, host_id FROM tasks
)`;

export async function getSwarmClusters(userId: string): Promise<SwarmClusterSummary[]> {
  const { rows } = await pool.query<{
    cluster_id: string;
    first_seen_at: Date | null;
    confirmed_at: Date | null;
    lm_id: string | null;
    lm_hostname: string | null;
    lm_label: string | null;
    services: string;
    degraded: string;
    managers: string;
    locked: string;
    nodes: string;
  }>(
    `WITH ${MY_CLUSTERS_CTE}
     SELECT ids.cluster_id, sc.first_seen_at, sc.confirmed_at,
            lm.id AS lm_id, lm.hostname AS lm_hostname, lm.label AS lm_label,
            (SELECT count(*) FROM svc WHERE svc.cluster_id = ids.cluster_id) AS services,
            (SELECT count(*) FROM svc WHERE svc.cluster_id = ids.cluster_id
               AND svc.running_tasks < svc.desired_tasks) AS degraded,
            (SELECT count(*) FROM host_docker hd JOIN my_hosts h ON h.id = hd.host_id
             WHERE hd.swarm_cluster_id = ids.cluster_id AND hd.swarm_role = 'manager') AS managers,
            (SELECT count(*) FROM host_docker hd JOIN my_hosts h ON h.id = hd.host_id
             WHERE hd.swarm_cluster_id = ids.cluster_id AND hd.swarm_state = 'locked') AS locked,
            (SELECT count(DISTINCT host_id) FROM nodes WHERE nodes.cluster_id = ids.cluster_id) AS nodes
     FROM ids
     LEFT JOIN swarm_clusters sc ON sc.user_id = $1 AND sc.cluster_id = ids.cluster_id
     LEFT JOIN my_hosts lm ON lm.id = sc.last_manager_host_id
     ORDER BY sc.first_seen_at NULLS LAST, ids.cluster_id`,
    [userId],
  );
  return rows.map((r) => ({
    clusterId: r.cluster_id,
    firstSeenAt: r.first_seen_at?.toISOString() ?? null,
    confirmedAt: r.confirmed_at?.toISOString() ?? null,
    lastManager: r.lm_id
      ? { hostId: r.lm_id, hostname: r.lm_hostname ?? "", label: r.lm_label }
      : null,
    services: Number(r.services),
    degraded: Number(r.degraded),
    managers: Number(r.managers),
    lockedManagers: Number(r.locked),
    nodes: Number(r.nodes),
  }));
}

// Swarm members that can't be placed in a cluster: workers aren't told the
// cluster id, so a worker is only attributed through its task containers.
export async function getUnattributedSwarmHosts(
  userId: string,
): Promise<(HostRef & { role: string | null; state: string | null })[]> {
  const { rows } = await pool.query<{
    host_id: string;
    hostname: string;
    label: string | null;
    swarm_role: string | null;
    swarm_state: string | null;
  }>(
    `WITH ${MY_CLUSTERS_CTE}
     SELECT h.id AS host_id, h.hostname, h.label, hd.swarm_role, hd.swarm_state
     FROM my_hosts h
     JOIN host_docker hd ON hd.host_id = h.id
     WHERE hd.swarm_state IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM nodes n WHERE n.host_id = h.id)
     ORDER BY lower(coalesce(h.label, h.hostname))`,
    [userId],
  );
  return rows.map((r) => ({
    hostId: r.host_id,
    hostname: r.hostname,
    label: r.label,
    role: r.swarm_role,
    state: r.swarm_state,
  }));
}

export type SwarmServicePort = {
  published?: number;
  target: number;
  proto: string;
  publish_mode: string;
};

export type SwarmTask = HostRef & {
  containerId: string;
  name: string;
  state: string | null;
  taskId: string | null;
  startedAt: string | null;
};

export type SwarmService = {
  serviceId: string;
  name: string;
  stack: string | null;
  image: string | null;
  mode: string | null;
  replicas: number | null;
  runningTasks: number | null;
  desiredTasks: number | null;
  ports: SwarmServicePort[];
  firstSeenAt: string;
  tasks: SwarmTask[]; // task containers reported by hosts with an agent
};

export type SwarmNode = HostRef & {
  role: string | null;
  state: string | null;
  nodeId: string | null;
  engineVersion: string | null;
  engineCollectedAt: string | null;
  runningTasks: number;
  tasks: number;
};

export type SwarmClusterDetail = {
  summary: SwarmClusterSummary;
  services: SwarmService[];
  nodes: SwarmNode[];
};

export async function getSwarmCluster(
  userId: string,
  clusterId: string,
): Promise<SwarmClusterDetail | null> {
  if (!isClusterId(clusterId)) return null;
  const summary = (await getSwarmClusters(userId)).find((c) => c.clusterId === clusterId);
  if (!summary) return null;

  const [services, tasks, nodes] = await Promise.all([
    pool.query<{
      service_id: string;
      name: string;
      swarm_stack: string | null;
      image: string | null;
      mode: string | null;
      replicas: number | null;
      running_tasks: number | null;
      desired_tasks: number | null;
      ports: SwarmServicePort[];
      first_seen_at: Date;
    }>(
      `SELECT ss.service_id, ss.name, ss.swarm_stack, ss.image, ss.mode, ss.replicas,
              ss.running_tasks, ss.desired_tasks, ss.ports, ss.first_seen_at
       FROM swarm_services ss
       WHERE ss.user_id = $1 AND ss.cluster_id = $2 AND ss.removed_at IS NULL
       ORDER BY ss.swarm_stack NULLS LAST, ss.name`,
      [userId, clusterId],
    ),
    pool.query<{
      service_id: string;
      host_id: string;
      hostname: string;
      label: string | null;
      container_id: string;
      name: string;
      state: string | null;
      swarm_task_id: string | null;
      started_at: Date | null;
    }>(
      `SELECT ss.service_id, h.id AS host_id, h.hostname, h.label,
              c.container_id, c.name, c.state, c.swarm_task_id, c.started_at
       FROM swarm_services ss
       JOIN host_containers c ON c.swarm_service_id = ss.service_id AND c.removed_at IS NULL
       JOIN hosts h ON h.id = c.host_id AND h.user_id = ss.user_id AND h.archived_at IS NULL
       WHERE ss.user_id = $1 AND ss.cluster_id = $2 AND ss.removed_at IS NULL
       ORDER BY c.state = 'running' DESC, lower(coalesce(h.label, h.hostname)), c.name`,
      [userId, clusterId],
    ),
    pool.query<{
      host_id: string;
      hostname: string;
      label: string | null;
      swarm_role: string | null;
      swarm_state: string | null;
      swarm_node_id: string | null;
      engine_version: string | null;
      engine_collected_at: Date | null;
      running: string;
      total: string;
    }>(
      `WITH ${MY_CLUSTERS_CTE}
       SELECT h.id AS host_id, h.hostname, h.label, hd.swarm_role, hd.swarm_state,
              hd.swarm_node_id, hd.engine_version, hd.engine_collected_at,
              (SELECT count(*) FROM tasks t WHERE t.cluster_id = $2 AND t.host_id = h.id
                 AND t.state = 'running') AS running,
              (SELECT count(*) FROM tasks t WHERE t.cluster_id = $2 AND t.host_id = h.id) AS total
       FROM my_hosts h
       LEFT JOIN host_docker hd ON hd.host_id = h.id
       WHERE h.id IN (SELECT host_id FROM nodes WHERE cluster_id = $2)
       ORDER BY hd.swarm_role = 'manager' DESC NULLS LAST, lower(coalesce(h.label, h.hostname))`,
      [userId, clusterId],
    ),
  ]);

  const byService = new Map<string, SwarmTask[]>();
  for (const t of tasks.rows) {
    const list = byService.get(t.service_id) ?? [];
    list.push({
      hostId: t.host_id,
      hostname: t.hostname,
      label: t.label,
      containerId: t.container_id,
      name: t.name,
      state: t.state,
      taskId: t.swarm_task_id,
      startedAt: t.started_at?.toISOString() ?? null,
    });
    byService.set(t.service_id, list);
  }

  return {
    summary,
    services: services.rows.map((s) => ({
      serviceId: s.service_id,
      name: s.name,
      stack: s.swarm_stack,
      image: s.image,
      mode: s.mode,
      replicas: s.replicas,
      runningTasks: s.running_tasks,
      desiredTasks: s.desired_tasks,
      ports: s.ports ?? [],
      firstSeenAt: s.first_seen_at.toISOString(),
      tasks: byService.get(s.service_id) ?? [],
    })),
    nodes: nodes.rows.map((n) => ({
      hostId: n.host_id,
      hostname: n.hostname,
      label: n.label,
      role: n.swarm_role,
      state: n.swarm_state,
      nodeId: n.swarm_node_id,
      engineVersion: n.engine_version,
      engineCollectedAt: n.engine_collected_at?.toISOString() ?? null,
      runningTasks: Number(n.running),
      tasks: Number(n.total),
    })),
  };
}
