import { pool } from "./db";
import type { ImageKey } from "./image-key";
import { imageScoreState, type ImageScore } from "./image-score";
import {
  IMAGE_SCORE_COLUMNS,
  type ImageScoreDbRow,
  mapImageScore,
  RELEASE_JOIN,
} from "./queries-image-scores";
import { emptySeverityCounts, isSeverity, type SeverityCounts } from "./severity";

// The Overview page's container image numbers (DOMAIN_MODEL.md §3.6
// "Overview", §2.6 "Image findings and scores"). Kept apart from the host
// package numbers on purpose: an image finding is fixed by rebuilding or
// re-pulling the image, a host one by upgrading the host.
//
// Tenancy: image_scores(user) has a row for every container_images key
// fleet-wide, so everything starts from the user's own current
// host_images on non-archived hosts.

// The user's inspected image keys (platform known) currently on a host,
// whether a current container on the same host uses the image, and whether
// any host has it with a repo digest (the server can fetch by digest).
const KEYS_CTE = `
k AS (
  SELECT hi.image_id, hi.os, hi.arch, hi.variant,
         bool_or(cardinality(array_remove(hi.repo_digests, '<none>@<none>')) > 0) AS has_digest,
         bool_or(EXISTS (
           SELECT 1 FROM host_containers c
           WHERE c.host_id = hi.host_id AND c.image_id = hi.image_id AND c.removed_at IS NULL
         )) AS in_use
  FROM hosts h
  JOIN host_images hi ON hi.host_id = h.id AND hi.removed_at IS NULL
  WHERE h.user_id = $1 AND h.archived_at IS NULL AND hi.os IS NOT NULL
  GROUP BY 1, 2, 3, 4
)`;

export type OverviewImage = {
  key: ImageKey;
  hasRepoDigest: boolean;
  score: ImageScore | null;
  // Tags across the user's hosts; empty = untagged (show the id).
  tags: string[];
  // Hosts with a current container using the image.
  hosts: { hostId: string; hostname: string; label: string | null; containers: string[] }[];
};

export type ImageOverviewStats = {
  // Any current image or container on the user's hosts. False = no Docker
  // data at all (the section collapses to one line).
  hasDocker: boolean;
  images: number; // inspected image keys
  scored: number; // keys with a current score
  vulnerable: number; // scored keys with at least one known vulnerability
  needsAgent: number; // private registry or local image: only the agent can list it
  noSbom: number; // unavailable for another reason (e.g. no SBOM attestation)
  failing: number; // package list fetch failed, retrying
  pending: number; // no list yet, or being scored
  // Open vulnerable_image findings (images a container uses).
  findings: {
    open: number;
    kev: number;
    fixable: number;
    hosts: number;
    images: number;
    bySeverity: SeverityCounts;
  };
  top: OverviewImage[]; // most vulnerable images in use, most urgent first
};

type KeyRow = ImageScoreDbRow & {
  image_id: string;
  os: string;
  arch: string;
  variant: string;
  has_digest: boolean;
  in_use: boolean;
  top_severity_key: string | null;
};

export async function getImageOverviewStats(userId: string, topN = 5): Promise<ImageOverviewStats> {
  const [docker, keys, sev, totals] = await Promise.all([
    pool.query<{ has: boolean }>(
      `SELECT EXISTS (
                SELECT 1 FROM hosts h
                JOIN host_images hi ON hi.host_id = h.id AND hi.removed_at IS NULL
                WHERE h.user_id = $1 AND h.archived_at IS NULL)
           OR EXISTS (
                SELECT 1 FROM hosts h
                JOIN host_containers c ON c.host_id = h.id AND c.removed_at IS NULL
                WHERE h.user_id = $1 AND h.archived_at IS NULL) AS has`,
      [userId],
    ),
    pool.query<KeyRow>(
      `WITH ${KEYS_CTE}
       SELECT k.image_id, k.os, k.arch, k.variant, k.has_digest, k.in_use,
              s.top_severity_key, ${IMAGE_SCORE_COLUMNS}
       FROM k
       LEFT JOIN image_scores($1) s
         ON s.image_id = k.image_id AND s.os = k.os AND s.arch = k.arch AND s.variant = k.variant
       ${RELEASE_JOIN}`,
      [userId],
    ),
    pool.query<{ severity: string | null; open: string }>(
      `SELECT f.severity, count(*) AS open
       FROM hosts h
       JOIN findings f ON f.host_id = h.id
       WHERE h.user_id = $1 AND h.archived_at IS NULL
         AND f.kind = 'vulnerable_image' AND f.status = 'open'
       GROUP BY f.severity`,
      [userId],
    ),
    pool.query<{ kev: string; fixable: string; hosts: string; images: string }>(
      `SELECT count(*) FILTER (WHERE f.is_kev) AS kev,
              count(*) FILTER (WHERE f.fix_channel = 'standard') AS fixable,
              count(DISTINCT f.host_id) AS hosts,
              count(DISTINCT concat_ws('|', f.image_id, f.image_os, f.image_arch, f.image_variant))
                AS images
       FROM hosts h
       JOIN findings f ON f.host_id = h.id
       WHERE h.user_id = $1 AND h.archived_at IS NULL
         AND f.kind = 'vulnerable_image' AND f.status = 'open'`,
      [userId],
    ),
  ]);

  let scored = 0;
  let vulnerable = 0;
  let needsAgent = 0;
  let noSbom = 0;
  let failing = 0;
  let pending = 0;
  const candidates: { row: KeyRow; score: ImageScore }[] = [];
  for (const r of keys.rows) {
    const score = mapImageScore(r);
    const st = imageScoreState(score, { inspected: true, hasRepoDigest: r.has_digest });
    if (score?.scored) scored++;
    switch (st.kind) {
      case "vulnerable":
        vulnerable++;
        if (r.in_use && score) candidates.push({ row: r, score });
        break;
      case "none":
        if (st.local) needsAgent++;
        else pending++;
        break;
      case "unavailable":
        if (st.needsAgent) needsAgent++;
        else noSbom++;
        break;
      case "error":
        failing++;
        break;
      case "scoring":
      case "not_inspected":
        pending++;
        break;
    }
  }
  // Worst first: the list's top severity key (same ranking as findings;
  // 37 bits, so exact as a Number), then the most vulnerabilities.
  const key = (x: string | null) => (x === null ? 0 : Number(x));
  candidates.sort(
    (a, b) =>
      key(b.row.top_severity_key) - key(a.row.top_severity_key) ||
      (b.score.vulns ?? 0) - (a.score.vulns ?? 0) ||
      a.row.image_id.localeCompare(b.row.image_id),
  );
  const top = candidates.slice(0, topN);

  const bySeverity = emptySeverityCounts();
  let open = 0;
  for (const r of sev.rows) {
    const n = Number(r.open);
    open += n;
    bySeverity[isSeverity(r.severity) ? r.severity : "unknown"] += n;
  }
  const t = totals.rows[0];

  return {
    hasDocker: docker.rows[0]?.has === true,
    images: keys.rows.length,
    scored,
    vulnerable,
    needsAgent,
    noSbom,
    failing,
    pending,
    findings: {
      open,
      kev: Number(t?.kev ?? 0),
      fixable: Number(t?.fixable ?? 0),
      hosts: Number(t?.hosts ?? 0),
      images: Number(t?.images ?? 0),
      bySeverity,
    },
    top: await withUsage(
      userId,
      top.map(({ row, score }) => ({
        key: { imageId: row.image_id, os: row.os, arch: row.arch, variant: row.variant },
        hasRepoDigest: row.has_digest,
        score,
        tags: [],
        hosts: [],
      })),
    ),
  };
}

// Tags and the hosts / containers using each image, for the few top images.
async function withUsage(userId: string, images: OverviewImage[]): Promise<OverviewImage[]> {
  if (images.length === 0) return images;
  const { rows } = await pool.query<{
    image_id: string;
    os: string;
    arch: string;
    variant: string;
    host_id: string;
    hostname: string;
    label: string | null;
    repo_tags: string[];
    containers: string[];
  }>(
    `SELECT hi.image_id, hi.os, hi.arch, hi.variant, h.id AS host_id, h.hostname, h.label,
            hi.repo_tags,
            ARRAY(SELECT c.name FROM host_containers c
                  WHERE c.host_id = h.id AND c.image_id = hi.image_id AND c.removed_at IS NULL
                  ORDER BY c.state = 'running' DESC, c.name) AS containers
     FROM unnest($2::text[], $3::text[], $4::text[], $5::text[]) AS key(image_id, os, arch, variant)
     JOIN host_images hi
       ON hi.image_id = key.image_id AND hi.os = key.os AND hi.arch = key.arch
      AND hi.variant = key.variant AND hi.removed_at IS NULL
     JOIN hosts h ON h.id = hi.host_id
     WHERE h.user_id = $1 AND h.archived_at IS NULL
     ORDER BY lower(coalesce(h.label, h.hostname)), h.id`,
    [
      userId,
      images.map((i) => i.key.imageId),
      images.map((i) => i.key.os),
      images.map((i) => i.key.arch),
      images.map((i) => i.key.variant),
    ],
  );
  const id = (k: ImageKey) => `${k.imageId}|${k.os}|${k.arch}|${k.variant}`;
  const byKey = new Map(images.map((i) => [id(i.key), i]));
  for (const r of rows) {
    const img = byKey.get(id({ imageId: r.image_id, os: r.os, arch: r.arch, variant: r.variant }));
    if (!img) continue;
    for (const t of r.repo_tags) {
      if (t !== "<none>:<none>" && !img.tags.includes(t)) img.tags.push(t);
    }
    if (r.containers.length > 0) {
      img.hosts.push({
        hostId: r.host_id,
        hostname: r.hostname,
        label: r.label,
        containers: r.containers,
      });
    }
  }
  for (const img of images) img.tags.sort();
  return images;
}

// ---------------------------------------------------------------------------
// Most urgent vulnerabilities across host packages and images
// ---------------------------------------------------------------------------

export type UrgentVulnRow = {
  vulnKey: string;
  severity: string | null;
  isKev: boolean;
  // Host package findings (vulnerable_package): hosts and source packages.
  hostPackageHosts: number;
  hostPackages: string[];
  // Image findings (vulnerable_image): distinct image keys, hosts, source
  // packages, and the most urgent image (for the link when there is one).
  images: number;
  imageHosts: number;
  imagePackages: string[];
  topImage: (ImageKey & { refs: string[] }) | null;
};

// One row per vuln_key over the user's open findings of both kinds, most
// urgent first (severity keys are the same ranking for both kinds). Where
// the CVE is stays visible per row: host packages and images are fixed
// differently.
export async function getUrgentVulns(userId: string, limit = 5): Promise<UrgentVulnRow[]> {
  const { rows } = await pool.query<{
    vuln_key: string;
    severity: string | null;
    is_kev: boolean;
    pkg_hosts: string;
    pkg_packages: (string | null)[] | null;
    images: string;
    image_hosts: string;
    image_packages: (string | null)[] | null;
    top_image: {
      imageId: string;
      os: string;
      arch: string;
      variant: string;
      refs: string[];
    } | null;
  }>(
    `WITH uf AS (
       SELECT f.*
       FROM hosts h
       JOIN findings f ON f.host_id = h.id
       WHERE h.user_id = $1 AND h.archived_at IS NULL AND f.status = 'open'
         AND f.kind IN ('vulnerable_package', 'vulnerable_image')
     )
     SELECT uf.vuln_key,
            (array_agg(uf.severity ORDER BY uf.severity_key DESC))[1] AS severity,
            bool_or(uf.is_kev) AS is_kev,
            count(DISTINCT uf.host_id) FILTER (WHERE uf.kind = 'vulnerable_package') AS pkg_hosts,
            array_agg(DISTINCT uf.source_package) FILTER (WHERE uf.kind = 'vulnerable_package')
              AS pkg_packages,
            count(DISTINCT concat_ws('|', uf.image_id, uf.image_os, uf.image_arch, uf.image_variant))
              FILTER (WHERE uf.kind = 'vulnerable_image') AS images,
            count(DISTINCT uf.host_id) FILTER (WHERE uf.kind = 'vulnerable_image') AS image_hosts,
            array_agg(DISTINCT uf.source_package) FILTER (WHERE uf.kind = 'vulnerable_image')
              AS image_packages,
            (array_agg(json_build_object(
               'imageId', uf.image_id, 'os', uf.image_os, 'arch', uf.image_arch,
               'variant', uf.image_variant, 'refs', uf.image_refs)
             ORDER BY uf.severity_key DESC) FILTER (WHERE uf.kind = 'vulnerable_image'))[1]
              AS top_image
     FROM uf
     WHERE uf.vuln_key IS NOT NULL
     GROUP BY uf.vuln_key
     ORDER BY max(uf.severity_key) DESC, count(DISTINCT uf.host_id) DESC, uf.vuln_key
     LIMIT $2`,
    [userId, limit],
  );
  const pkgs = (xs: (string | null)[] | null) => (xs ?? []).filter((p): p is string => p !== null);
  return rows.map((r) => ({
    vulnKey: r.vuln_key,
    severity: r.severity,
    isKev: r.is_kev,
    hostPackageHosts: Number(r.pkg_hosts),
    hostPackages: pkgs(r.pkg_packages),
    images: Number(r.images),
    imageHosts: Number(r.image_hosts),
    imagePackages: pkgs(r.image_packages),
    topImage: r.top_image,
  }));
}
