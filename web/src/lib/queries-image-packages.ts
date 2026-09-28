import { assessedSql } from "./assessed";
import { pool } from "./db";
import type { ImageKey } from "./image-key";
import type { ImagePackageSort, ImagePackageStatus } from "./image-tables";
import { isSeverity, type Severity } from "./severity";
import { BUCKET_NAMES_SQL, severityLateral } from "./severity-sql";

// The image detail page's Packages tab: every package of the image's
// effective list (image_sbom_effective(user), migration 0014), vulnerable
// or not, with its matches from software_vulnerabilities. Server-driven:
// search, facets, sort and paging happen here in SQL.
//
// A package's status, in order: vulnerable (has matches), pending (the
// matcher hasn't evaluated the version yet), not assessed (ecosystem /
// distro the matcher doesn't cover, matcher.Assessed mirrored in
// assessed.ts, or a release out of support: distro_releases.supported),
// else no known vulnerabilities. Worst severity per package is over its
// own matches (severity-sql.ts); the Vulnerabilities tab groups by source
// package as findings do.

export type ImagePackageRow = {
  softwareId: string;
  name: string;
  version: string;
  arch: string;
  ecosystem: string;
  distro: string;
  release: string;
  sourceName: string | null;
  sourceVersion: string | null;
  paths: string[];
  status: ImagePackageStatus;
  releaseSupported: boolean | null; // distro_releases.supported (distro packages)
  vulns: number;
  worst: Severity | null;
  kev: number;
  fixable: number;
  unfixed: number;
  maxFixedVersion: string | null;
};

export type ImagePackageFilters = {
  q: string | null;
  ecosystems: string[] | null;
  statuses: ImagePackageStatus[] | null;
  sort: { id: ImagePackageSort; desc: boolean };
  page: number; // 1-based
  pageSize: number;
};

// The list's rows with their match summary; $1..$5 = user, image key.
const PACKAGES_CTE = `
pk AS (
  SELECT sv.id, sv.ecosystem, sv.distro, sv.release, sv.name, sv.version, sv.arch,
         sv.source_name, sv.source_version, sv.matcher_version, sv.max_fixed_version,
         isw.paths, dr.supported AS release_supported,
         ${assessedSql("sv.ecosystem", "sv.distro", "sv.release")}
           AND (sv.distro = '' OR coalesce(dr.supported, false)) AS assessed
  FROM image_sbom_effective($1) e
  JOIN image_software isw ON isw.sbom_id = e.sbom_id
  JOIN software_versions sv ON sv.id = isw.software_id
  LEFT JOIN distro_releases dr ON dr.distro = sv.distro AND dr.codename = sv.release
  WHERE e.image_id = $2 AND e.os = $3 AND e.arch = $4 AND e.variant = $5
),
v AS (
  SELECT sw.software_id, count(*) AS vulns, max(sev.bucket) AS worst_rank,
         max(sev.severity_key) AS top_key,
         count(*) FILTER (WHERE c.is_kev) AS kev,
         count(*) FILTER (WHERE sw.fix_channel = 'standard') AS fixable,
         count(*) FILTER (WHERE sw.fixed_version IS NULL) AS unfixed
  FROM pk
  JOIN software_vulnerabilities sw ON sw.software_id = pk.id
  LEFT JOIN cves c ON c.id = sw.vuln_key AND sw.vuln_key LIKE 'CVE-%'
  ${severityLateral("sev", {
    distroSeverity: "sw.distro_severity",
    fixChannel: "sw.fix_channel",
    kev: "c.is_kev",
    epss: "c.epss_score",
    cvss: "c.cvss_v3_score",
  })}
  GROUP BY sw.software_id
),
r AS (
  SELECT pk.*, coalesce(v.vulns, 0) AS vulns, v.worst_rank, coalesce(v.top_key, 0) AS top_key,
         coalesce(v.kev, 0) AS kev, coalesce(v.fixable, 0) AS fixable,
         coalesce(v.unfixed, 0) AS unfixed,
         CASE WHEN coalesce(v.vulns, 0) > 0 THEN 'vulnerable'
              WHEN pk.matcher_version IS NULL AND pk.assessed THEN 'pending'
              WHEN NOT pk.assessed THEN 'not-assessed'
              ELSE 'no-known' END AS status
  FROM pk LEFT JOIN v ON v.software_id = pk.id
)`;

export async function getImagePackages(
  userId: string,
  key: ImageKey,
  f: ImagePackageFilters,
): Promise<{ rows: ImagePackageRow[]; total: number }> {
  // Static ORDER BY variants (allowlisted id and direction).
  const dir = f.sort.desc ? "DESC" : "ASC";
  const orderBy = {
    status: `top_key ${dir}, vulns ${dir}, lower(name), version, id`,
    name: `lower(name) ${dir}, version ${dir}, id`,
    ecosystem: `ecosystem ${dir}, lower(name), version, id`,
  }[f.sort.id];
  const { rows } = await pool.query<{
    id: string;
    ecosystem: string;
    distro: string;
    release: string;
    name: string;
    version: string;
    arch: string;
    source_name: string | null;
    source_version: string | null;
    max_fixed_version: string | null;
    paths: string[];
    release_supported: boolean | null;
    status: ImagePackageStatus;
    vulns: string;
    worst: string | null;
    kev: string;
    fixable: string;
    unfixed: string;
    total: string;
  }>(
    `WITH ${PACKAGES_CTE}
     SELECT r.*, ${BUCKET_NAMES_SQL}[r.worst_rank] AS worst, count(*) OVER () AS total
     FROM r
     WHERE ($6::text IS NULL
            OR strpos(lower(r.name), lower($6)) > 0
            OR strpos(lower(coalesce(r.source_name, '')), lower($6)) > 0
            OR EXISTS (SELECT 1 FROM unnest(r.paths) p WHERE strpos(lower(p), lower($6)) > 0))
       AND ($7::text[] IS NULL OR r.ecosystem = ANY($7))
       AND ($8::text[] IS NULL OR r.status = ANY($8))
     ORDER BY ${orderBy}
     LIMIT $9 OFFSET $10`,
    [
      userId,
      key.imageId,
      key.os,
      key.arch,
      key.variant,
      f.q,
      f.ecosystems,
      f.statuses,
      f.pageSize,
      (f.page - 1) * f.pageSize,
    ],
  );
  return {
    rows: rows.map((r) => ({
      softwareId: String(r.id),
      name: r.name,
      version: r.version,
      arch: r.arch,
      ecosystem: r.ecosystem,
      distro: r.distro,
      release: r.release,
      sourceName: r.source_name,
      sourceVersion: r.source_version,
      paths: r.paths,
      status: r.status,
      releaseSupported: r.release_supported,
      vulns: Number(r.vulns),
      worst: isSeverity(r.worst) ? r.worst : null,
      kev: Number(r.kev),
      fixable: Number(r.fixable),
      unfixed: Number(r.unfixed),
      maxFixedVersion: r.max_fixed_version,
    })),
    total: rows[0] ? Number(rows[0].total) : 0,
  };
}

// Ecosystems in the image's list, most packages first (the facet options).
export async function getImageEcosystems(
  userId: string,
  key: ImageKey,
): Promise<{ ecosystem: string; packages: number }[]> {
  const { rows } = await pool.query<{ ecosystem: string; n: string }>(
    `SELECT sv.ecosystem, count(*) AS n
     FROM image_sbom_effective($1) e
     JOIN image_software isw ON isw.sbom_id = e.sbom_id
     JOIN software_versions sv ON sv.id = isw.software_id
     WHERE e.image_id = $2 AND e.os = $3 AND e.arch = $4 AND e.variant = $5
     GROUP BY 1
     ORDER BY 2 DESC, 1`,
    [userId, key.imageId, key.os, key.arch, key.variant],
  );
  return rows.map((r) => ({ ecosystem: r.ecosystem, packages: Number(r.n) }));
}
