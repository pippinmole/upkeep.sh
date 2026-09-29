import { cache } from "react";

import { pool } from "./db";
import type { ImageScore } from "./image-score";
import { isImageId, type ImageKey } from "./image-key";
import { isUuid } from "./queries-inventory";
import {
  IMAGE_SCORE_COLUMNS,
  type ImageScoreDbRow,
  mapImageScore,
  RELEASE_JOIN,
} from "./queries-image-scores";

// One container image (docs/tasks/phase-2a-image-vulns.md "Dashboard", DOMAIN_MODEL.md
// §3.8): which of the user's hosts have it, the containers using it, its
// package list's provenance and its score. Packages and vulnerabilities
// are in queries-image-packages.ts / queries-image-vulns.ts.
//
// Tenancy: container_images, image_sbom_state and image_software are
// shared ACROSS USERS (server lists are fleet-wide per image key). Every
// read here starts from the user's own current host_images rows
// (`hosts.workspace_id = $1`, not archived, `removed_at IS NULL`); an image the
// user doesn't have is a 404, whatever the id. Package lists are only
// reached through image_sbom_effective(user), which never returns another
// user's agent list.

// The image's platforms on the user's hosts. `platforms` are the inspected
// keys (ordered, the host's first when hostId is given); `uninspected` is
// true when some host has the id without a known platform yet.
export type ImagePlatforms = { platforms: ImageKey[]; uninspected: boolean };

export const getImagePlatforms = cache(async function getImagePlatforms(
  workspaceId: string,
  imageId: string,
  hostId: string | null,
): Promise<ImagePlatforms | null> {
  if (!isImageId(imageId)) return null;
  const { rows } = await pool.query<{
    os: string | null;
    arch: string | null;
    variant: string | null;
    on_host: boolean;
  }>(
    `SELECT hi.os, hi.arch, hi.variant, bool_or(h.id::text = $3) AS on_host
     FROM hosts h
     JOIN host_images hi ON hi.host_id = h.id AND hi.removed_at IS NULL
     WHERE h.workspace_id = $1 AND h.archived_at IS NULL AND hi.image_id = $2
     GROUP BY 1, 2, 3
     ORDER BY on_host DESC, hi.os NULLS LAST, hi.arch, hi.variant`,
    [workspaceId, imageId, hostId && isUuid(hostId) ? hostId : ""],
  );
  if (rows.length === 0) return null;
  const platforms: ImageKey[] = [];
  let uninspected = false;
  for (const r of rows) {
    if (r.os === null || r.arch === null || r.variant === null) uninspected = true;
    else platforms.push({ imageId, os: r.os, arch: r.arch, variant: r.variant });
  }
  return { platforms, uninspected };
});

export type ImageContainerRef = {
  id: string;
  name: string;
  state: string | null;
  composeProject: string | null;
  swarmServiceName: string | null;
};

export type ImageHost = {
  hostId: string;
  hostname: string;
  label: string | null;
  tags: string[];
  digests: string[];
  containers: ImageContainerRef[];
  // Open vulnerable_image findings for this image on the host.
  openFindings: number;
};

// The list the score and packages come from, or why there is none: the
// effective ok list (server's, else the user's agent list), else the most
// recently updated failed row, as image_scores picks them.
export type ImageListState = {
  status: "ok" | "unavailable" | "error";
  reason: string | null;
  source: string | null; // attestation | server-syft | agent-syft
  toolName: string | null;
  toolVersion: string | null;
  generatedAt: string | null;
  packageCount: number | null;
  distro: string | null;
  distroVersion: string | null;
  distroName: string | null;
  release: string | null;
  releaseSupported: boolean | null;
  releaseEol: string | null;
  attempts: number;
  lastAttemptAt: string | null;
  nextAttemptAt: string | null;
};

export type ImageOverview = {
  key: ImageKey;
  tags: string[]; // repo tags across the user's hosts
  digests: string[]; // repo digests across the user's hosts
  created: string | null;
  hosts: ImageHost[];
  score: ImageScore | null;
  list: ImageListState | null; // null = nothing attempted yet
};

export const getImageOverview = cache(async function getImageOverview(
  workspaceId: string,
  key: ImageKey,
): Promise<ImageOverview | null> {
  const k = [workspaceId, key.imageId, key.os, key.arch, key.variant];
  const [hosts, score, list] = await Promise.all([
    pool.query<{
      host_id: string;
      hostname: string;
      label: string | null;
      repo_tags: string[];
      repo_digests: string[];
      created: Date | null;
      containers: ImageContainerRef[];
      open_findings: string;
    }>(
      `SELECT h.id AS host_id, h.hostname, h.label, hi.repo_tags, hi.repo_digests, ci.created,
              coalesce((
                SELECT json_agg(json_build_object(
                         'id', c.container_id, 'name', c.name, 'state', c.state,
                         'composeProject', c.compose_project,
                         'swarmServiceName', c.swarm_service_name)
                       ORDER BY c.state = 'running' DESC, c.name)
                FROM host_containers c
                WHERE c.host_id = h.id AND c.image_id = hi.image_id AND c.removed_at IS NULL
              ), '[]') AS containers,
              (SELECT count(*) FROM findings f
               WHERE f.host_id = h.id AND f.kind = 'vulnerable_image' AND f.status = 'open'
                 AND f.image_id = hi.image_id AND f.image_os = hi.os
                 AND f.image_arch = hi.arch AND f.image_variant = hi.variant) AS open_findings
       FROM hosts h
       JOIN host_images hi ON hi.host_id = h.id AND hi.removed_at IS NULL
       JOIN container_images ci
         ON ci.image_id = hi.image_id AND ci.os = hi.os AND ci.arch = hi.arch AND ci.variant = hi.variant
       WHERE h.workspace_id = $1 AND h.archived_at IS NULL
         AND hi.image_id = $2 AND hi.os = $3 AND hi.arch = $4 AND hi.variant = $5
       ORDER BY lower(coalesce(h.label, h.hostname)), h.id`,
      k,
    ),
    pool.query<ImageScoreDbRow>(
      `SELECT ${IMAGE_SCORE_COLUMNS}
       FROM image_scores($1) s
       ${RELEASE_JOIN}
       WHERE s.image_id = $2 AND s.os = $3 AND s.arch = $4 AND s.variant = $5`,
      k,
    ),
    // Same pick as image_scores: the effective ok list, else the newest
    // failed row of the server's and the user's.
    pool.query<{
      status: ImageListState["status"];
      reason: string | null;
      source: string | null;
      tool_name: string | null;
      tool_version: string | null;
      generated_at: Date | null;
      package_count: number | null;
      distro: string | null;
      distro_version: string | null;
      distro_name: string | null;
      release: string | null;
      supported: boolean | null;
      eol_date: string | null; // YYYY-MM-DD
      attempts: number;
      last_attempt_at: Date | null;
      next_attempt_at: Date | null;
    }>(
      `SELECT st.status, st.reason, st.source, st.tool_name, st.tool_version, st.generated_at,
              st.package_count, st.distro, st.distro_version, st.distro_name, st.release,
              dr.supported, to_char(dr.eol_date, 'YYYY-MM-DD') AS eol_date, st.attempts,
              st.last_attempt_at, st.next_attempt_at
       FROM image_sbom_state st
       LEFT JOIN distro_releases dr ON dr.distro = st.distro AND dr.codename = st.release
       WHERE st.image_id = $2 AND st.os = $3 AND st.arch = $4 AND st.variant = $5
         AND (st.owner_workspace_id IS NULL OR st.owner_workspace_id = $1)
       ORDER BY st.status = 'ok' DESC, (st.status = 'ok' AND st.owner_workspace_id IS NULL) DESC,
                st.updated_at DESC, st.id DESC
       LIMIT 1`,
      k,
    ),
  ]);
  if (hosts.rows.length === 0) return null;

  const uniq = (xs: string[]) => [...new Set(xs)].sort();
  const l = list.rows[0];
  return {
    key,
    tags: uniq(hosts.rows.flatMap((r) => r.repo_tags.filter((t) => t !== "<none>:<none>"))),
    digests: uniq(hosts.rows.flatMap((r) => r.repo_digests.filter((d) => d !== "<none>@<none>"))),
    created: hosts.rows[0].created?.toISOString() ?? null,
    hosts: hosts.rows.map((r) => ({
      hostId: r.host_id,
      hostname: r.hostname,
      label: r.label,
      tags: r.repo_tags,
      digests: r.repo_digests,
      containers: r.containers,
      openFindings: Number(r.open_findings),
    })),
    score: score.rows[0] ? mapImageScore(score.rows[0]) : null,
    list: l
      ? {
          status: l.status,
          reason: l.reason,
          source: l.source,
          toolName: l.tool_name,
          toolVersion: l.tool_version,
          generatedAt: l.generated_at?.toISOString() ?? null,
          packageCount: l.package_count,
          distro: l.distro,
          distroVersion: l.distro_version,
          distroName: l.distro_name,
          release: l.release,
          releaseSupported: l.supported,
          releaseEol: l.eol_date,
          attempts: l.attempts,
          lastAttemptAt: l.last_attempt_at?.toISOString() ?? null,
          nextAttemptAt: l.next_attempt_at?.toISOString() ?? null,
        }
      : null,
  };
});
