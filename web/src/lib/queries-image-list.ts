import { pool } from "./db";
import type { ImageKey } from "./image-key";
import type { ImageScore } from "./image-score";
import {
  IMAGE_SCORE_COLUMNS,
  type ImageScoreDbRow,
  mapImageScore,
  RELEASE_JOIN,
} from "./queries-image-scores";
import { SCORED_LIST_SQL } from "./queries-image-vulns";

// Image reads for the MCP image tools (docs/MCP.md#tools): every inspected
// image key on the workspace's hosts with its score (image_scores(user),
// as the fleet Images page and the Overview read it) and where it runs
// (list_images), and an image's vulnerabilities counted by ecosystem
// (get_image_vulnerabilities' origin summary).
//
// Tenancy as in queries-docker-fleet.ts: container_images and the score
// read model are fleet-wide, so every read starts from the workspace's own
// current host_images on non-archived hosts.

export type ImageListHost = {
  hostId: string;
  hostname: string;
  label: string | null;
  // Running containers using the image on this host.
  containers: string[];
};

export type ImageListRow = {
  key: ImageKey;
  // Tags and repo digests across the workspace's hosts, sorted.
  refs: string[];
  hasRepoDigest: boolean;
  score: ImageScore | null;
  // Open vulnerable_image findings (images a container uses).
  openFindings: number;
  hosts: ImageListHost[];
};

export type ImageListQuery = {
  // Substring of a tag, digest or the image id, case-insensitive.
  q: string | null;
  limit: number;
};

// Most urgent first: the score's top severity, then the most
// vulnerabilities, then by name.
export async function getImageList(
  workspaceId: string,
  f: ImageListQuery,
): Promise<{ rows: ImageListRow[]; total: number }> {
  const { rows } = await pool.query<
    ImageScoreDbRow & {
      image_id: string;
      os: string;
      arch: string;
      variant: string;
      refs: string[] | null;
      has_digest: boolean;
      open_findings: string;
      hosts: ImageListHost[];
      total: string;
    }
  >(
    `WITH hk AS (
       SELECT h.id AS host_id, h.hostname, h.label, hi.image_id, hi.os, hi.arch, hi.variant,
              array_remove(array_remove(hi.repo_tags || hi.repo_digests, '<none>:<none>'),
                           '<none>@<none>') AS refs,
              cardinality(array_remove(hi.repo_digests, '<none>@<none>')) > 0 AS has_digest,
              ARRAY(SELECT c.name FROM host_containers c
                    WHERE c.host_id = h.id AND c.image_id = hi.image_id
                      AND c.removed_at IS NULL AND c.state = 'running'
                    ORDER BY c.name) AS running
       FROM hosts h
       JOIN host_images hi ON hi.host_id = h.id AND hi.removed_at IS NULL
       WHERE h.workspace_id = $1 AND h.archived_at IS NULL AND hi.os IS NOT NULL
     ),
     k AS (
       SELECT image_id, os, arch, variant, bool_or(has_digest) AS has_digest,
              json_agg(json_build_object('hostId', host_id, 'hostname', hostname,
                                         'label', label, 'containers', running)
                       ORDER BY lower(coalesce(label, hostname)), host_id) AS hosts
       FROM hk
       GROUP BY image_id, os, arch, variant
     ),
     kr AS (
       SELECT k.*,
              (SELECT array_agg(DISTINCT r ORDER BY r)
               FROM hk, unnest(hk.refs) r
               WHERE hk.image_id = k.image_id AND hk.os = k.os AND hk.arch = k.arch
                 AND hk.variant = k.variant) AS refs
       FROM k
     )
     SELECT kr.image_id, kr.os, kr.arch, kr.variant, kr.refs, kr.has_digest, kr.hosts,
            (SELECT count(*) FROM hosts h
             JOIN findings f ON f.host_id = h.id
             WHERE h.workspace_id = $1 AND h.archived_at IS NULL
               AND f.kind = 'vulnerable_image' AND f.status = 'open'
               AND f.image_id = kr.image_id AND f.image_os = kr.os
               AND f.image_arch = kr.arch AND f.image_variant = kr.variant) AS open_findings,
            ${IMAGE_SCORE_COLUMNS},
            count(*) OVER () AS total
     FROM kr
     LEFT JOIN image_scores($1) s
       ON s.image_id = kr.image_id AND s.os = kr.os AND s.arch = kr.arch AND s.variant = kr.variant
     ${RELEASE_JOIN}
     WHERE $2::text IS NULL
        OR strpos(kr.image_id, lower($2)) > 0
        OR EXISTS (SELECT 1 FROM unnest(kr.refs) r WHERE strpos(lower(r), lower($2)) > 0)
     ORDER BY s.top_severity_key DESC NULLS LAST, s.vuln_count DESC NULLS LAST,
              kr.refs[1] NULLS LAST, kr.image_id, kr.os, kr.arch, kr.variant
     LIMIT $3`,
    [workspaceId, f.q, f.limit],
  );
  return {
    rows: rows.map((r) => ({
      key: { imageId: r.image_id, os: r.os, arch: r.arch, variant: r.variant },
      refs: r.refs ?? [],
      hasRepoDigest: r.has_digest,
      score: mapImageScore(r),
      openFindings: Number(r.open_findings),
      hosts: r.hosts,
    })),
    total: rows[0] ? Number(rows[0].total) : 0,
  };
}

export type ImageEcosystemCount = {
  ecosystem: string;
  vulns: number;
  // Fixed in the normal archive or the package's own registry.
  fixable: number;
  kev: number;
};

// The image's Vulnerabilities tab rows (image_sbom_vulns of the effective
// list, while its score is current) counted per ecosystem, with the
// severity and KEV filters of getImageVulns.
export async function getImageVulnEcosystems(
  workspaceId: string,
  key: ImageKey,
  f: { severities: string[] | null; kev: boolean },
): Promise<ImageEcosystemCount[]> {
  const { rows } = await pool.query<{
    ecosystem: string;
    vulns: string;
    fixable: string;
    kev: string;
  }>(
    `SELECT v.ecosystem, count(*) AS vulns,
            count(*) FILTER (WHERE v.fix_channel = 'standard') AS fixable,
            count(*) FILTER (WHERE v.is_kev) AS kev
     FROM (${SCORED_LIST_SQL}) l
     JOIN image_sbom_vulns v ON v.sbom_id = l.sbom_id
     WHERE ($6::text[] IS NULL OR v.severity = ANY($6))
       AND (NOT $7::boolean OR v.is_kev)
     GROUP BY v.ecosystem
     ORDER BY v.ecosystem`,
    [workspaceId, key.imageId, key.os, key.arch, key.variant, f.severities, f.kev],
  );
  return rows.map((r) => ({
    ecosystem: r.ecosystem,
    vulns: Number(r.vulns),
    fixable: Number(r.fixable),
    kev: Number(r.kev),
  }));
}
