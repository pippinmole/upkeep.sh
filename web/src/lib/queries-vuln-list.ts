import { pool } from "./db";
import { isUuid } from "./queries-inventory";
import { FINDING_COLUMNS, type FindingDbRow, type FindingRow, mapFinding } from "./queries-vulns";
import type { Severity } from "./severity";
import {
  FINDING_KIND,
  VULN_KINDS,
  type FleetVulnSort,
  type HostVulnSort,
  type ImageWhere,
  type VulnFix,
  type VulnKind,
} from "./vuln-tables";

// The fleet Vulnerabilities list and the host Vulnerabilities tab
// (DOMAIN_MODEL.md §3.5, §3.6): findings of both kinds, host packages
// (vulnerable_package) and container images (vulnerable_image), in one
// server-driven table with a Kind facet. Counts are per kind and never
// summed: an image is fixed by rebuilding or re-pulling it, a host package
// by upgrading the host.
//
// Tenancy as in queries-vulns.ts: every read starts from the user's hosts
// (`h.user_id = $1`); fleet-wide reads skip archived hosts.

const num = (v: string | null): number | null => (v === null ? null : Number(v));

// ?kind= -> findings.kind values; no filter = both.
function findingKinds(kinds: VulnKind[] | null): string[] {
  return (kinds && kinds.length > 0 ? kinds : VULN_KINDS).map((k) => FINDING_KIND[k]);
}

// ?q= over a findings row `f` (q bound at $n): vuln key, source or binary
// package, image ref or container name.
function qMatchSql(n: number, f = "f"): string {
  return `($${n}::text IS NULL
            OR strpos(lower(${f}.vuln_key), lower($${n})) > 0
            OR strpos(lower(coalesce(${f}.source_package, '')), lower($${n})) > 0
            OR EXISTS (SELECT 1 FROM unnest(${f}.packages || ${f}.image_refs || ${f}.container_names) x
                       WHERE strpos(lower(x), lower($${n})) > 0))`;
}

// ---------------------------------------------------------------------------
// Host tab: one row per finding
// ---------------------------------------------------------------------------

export type HostVulnListFilters = {
  status: "open" | "resolved";
  q: string | null; // vuln key, package, image ref or container substring
  kinds: VulnKind[] | null;
  severities: Severity[] | null;
  kev: boolean;
  fix: VulnFix[] | null;
  sort: { id: HostVulnSort; desc: boolean };
  page: number;
  pageSize: number;
};

export async function getHostVulnList(
  userId: string,
  hostId: string,
  f: HostVulnListFilters,
): Promise<{ rows: FindingRow[]; total: number }> {
  if (!isUuid(hostId)) return { rows: [], total: 0 };
  const dir = f.sort.desc ? "DESC" : "ASC";
  const seen = f.status === "resolved" ? "f.resolved_at" : "f.first_seen_at";
  // Static ORDER BY variants; the open + severity form walks
  // findings_host_open_rank_idx.
  const orderBy = {
    severity: `f.severity_key ${dir}, f.vuln_key, f.source_package`,
    vuln: `f.vuln_key ${dir}, f.severity_key DESC, f.source_package`,
    seen: `${seen} ${dir}, f.severity_key DESC, f.vuln_key`,
  }[f.sort.id];
  const { rows } = await pool.query<FindingDbRow & { total: string }>(
    `SELECT ${FINDING_COLUMNS}, left(c.description, 240) AS description,
            count(*) OVER () AS total
     FROM hosts h
     JOIN findings f ON f.host_id = h.id
     LEFT JOIN cves c ON c.id = f.vuln_key
     WHERE h.id = $2 AND h.user_id = $1
       AND f.kind = ANY($3::text[]) AND f.status = $4
       AND ${qMatchSql(5)}
       AND ($6::text[] IS NULL OR f.severity = ANY($6))
       AND (NOT $7::boolean OR f.is_kev)
       AND ($8::text[] IS NULL
            OR ('available' = ANY($8) AND f.fix_channel = 'standard')
            OR ('pro' = ANY($8) AND f.requires_pro)
            OR ('none' = ANY($8) AND f.fixed_version IS NULL))
     ORDER BY ${orderBy}
     LIMIT $9 OFFSET $10`,
    [
      userId,
      hostId,
      findingKinds(f.kinds),
      f.status,
      f.q,
      f.severities,
      f.kev,
      f.fix,
      f.pageSize,
      (f.page - 1) * f.pageSize,
    ],
  );
  return { rows: rows.map(mapFinding), total: rows[0] ? Number(rows[0].total) : 0 };
}

// ---------------------------------------------------------------------------
// Fleet list: one row per (vuln_key, host packages) and (vuln_key, image key)
// ---------------------------------------------------------------------------

export type FleetVulnRow = {
  vulnKey: string;
  kind: VulnKind;
  // The image, its refs (repo:tag) and the containers using it on the
  // user's hosts; null for a host package row.
  image: ImageWhere | null;
  severity: string | null;
  isKev: boolean;
  epssScore: number | null;
  cvssV3Score: number | null;
  affectedHosts: number; // hosts with an open finding
  previousHosts: number; // hosts with a resolved finding only
  packages: string[]; // source packages
  // Image rows: installed and fixed version per source package in the image.
  imageFixes: {
    sourcePackage: string;
    installedVersion: string | null;
    fixedVersion: string | null;
  }[];
  anyFix: boolean; // a standard-archive fix exists for some affected host / the image
  proOnly: boolean; // some affected host's only fix is Ubuntu Pro
  noFix: boolean; // some affected package has no fix at all
  firstSeenAt: string;
  description: string | null;
};

export type FleetVulnListFilters = Omit<HostVulnListFilters, "sort"> & {
  sort: { id: FleetVulnSort; desc: boolean };
};

type FleetDbRow = {
  vuln_key: string;
  is_image: boolean;
  image_id: string | null;
  image_os: string | null;
  image_arch: string | null;
  image_variant: string | null;
  severity: string | null;
  is_kev: boolean;
  epss_score: string | null;
  cvss_v3_score: string | null;
  affected_hosts: string;
  previous_hosts: string;
  packages: (string | null)[] | null;
  any_fix: boolean;
  pro_only: boolean;
  no_fix: boolean;
  first_seen_at: Date;
  description: string | null;
  refs: string[] | null;
  containers: string[] | null;
  image_fixes: FleetVulnRow["imageFixes"] | null;
  total: string;
};

function mapFleetRow(r: FleetDbRow): FleetVulnRow {
  return {
    vulnKey: r.vuln_key,
    kind: r.is_image ? "image" : "package",
    image:
      r.is_image && r.image_id !== null
        ? {
            imageId: r.image_id,
            os: r.image_os ?? "",
            arch: r.image_arch ?? "",
            variant: r.image_variant ?? "",
            refs: r.refs ?? [],
            containers: r.containers ?? [],
          }
        : null,
    severity: r.severity,
    isKev: r.is_kev,
    epssScore: num(r.epss_score),
    cvssV3Score: num(r.cvss_v3_score),
    affectedHosts: Number(r.affected_hosts),
    previousHosts: Number(r.previous_hosts),
    packages: (r.packages ?? []).filter((p): p is string => p !== null),
    imageFixes: (r.image_fixes ?? []).sort((a, b) =>
      a.sourcePackage.localeCompare(b.sourcePackage),
    ),
    anyFix: r.any_fix,
    proOnly: r.pro_only,
    noFix: r.no_fix,
    firstSeenAt: r.first_seen_at.toISOString(),
    description: r.description,
  };
}

// "open" lists groups with an open finding on some host now; "resolved"
// lists groups whose findings are all resolved. Host package and image
// groups are separate rows, so a CVE fixed in host packages but still in
// an image is resolved in one and open in the other. Severity and fix
// columns come from the findings of the listed status.
export async function getFleetVulnList(
  userId: string,
  f: FleetVulnListFilters,
): Promise<{ rows: FleetVulnRow[]; total: number }> {
  const dir = f.sort.desc ? "DESC" : "ASC";
  // Every variant ends in the group key, so paging is stable.
  const tie = "g.vuln_key, g.is_image, g.image_id, g.image_os, g.image_arch, g.image_variant";
  const orderBy = {
    severity: `g.top_key ${dir}, g.affected_hosts DESC, ${tie}`,
    vuln: `g.vuln_key ${dir}, g.top_key DESC, ${tie}`,
    hosts: `g.affected_hosts ${dir}, g.top_key DESC, ${tie}`,
    first_seen: `g.first_seen_at ${dir}, g.top_key DESC, ${tie}`,
  }[f.sort.id];
  const { rows } = await pool.query<FleetDbRow>(
    `WITH uf AS (
       SELECT f.*, f.kind = 'vulnerable_image' AS is_image
       FROM hosts h
       JOIN findings f ON f.host_id = h.id
       WHERE h.user_id = $1 AND h.archived_at IS NULL AND f.kind = ANY($3::text[])
         AND f.vuln_key IS NOT NULL
     ),
     g AS (
       SELECT uf.vuln_key, uf.is_image, uf.image_id, uf.image_os, uf.image_arch, uf.image_variant,
              count(DISTINCT uf.host_id) FILTER (WHERE uf.status = 'open') AS affected_hosts,
              count(DISTINCT uf.host_id) FILTER (WHERE uf.status = 'resolved') AS previous_hosts,
              max(uf.severity_key) FILTER (WHERE uf.status = $2) AS top_key,
              (array_agg(uf.severity ORDER BY uf.severity_key DESC)
                 FILTER (WHERE uf.status = $2))[1] AS severity,
              bool_or(uf.is_kev) AS is_kev,
              max(uf.epss_score) AS epss_score,
              max(uf.cvss_v3_score) AS cvss_v3_score,
              array_agg(DISTINCT uf.source_package) FILTER (WHERE uf.status = $2) AS packages,
              coalesce(bool_or(uf.fix_channel = 'standard') FILTER (WHERE uf.status = $2), false) AS any_fix,
              coalesce(bool_or(uf.requires_pro) FILTER (WHERE uf.status = $2), false) AS pro_only,
              coalesce(bool_or(uf.fixed_version IS NULL) FILTER (WHERE uf.status = $2), false) AS no_fix,
              min(uf.first_seen_at) AS first_seen_at,
              bool_or(${qMatchSql(4, "uf")}) AS q_match
       FROM uf
       GROUP BY uf.vuln_key, uf.is_image, uf.image_id, uf.image_os, uf.image_arch, uf.image_variant
     ),
     page AS (
       SELECT g.*, count(*) OVER () AS total
       FROM g
       WHERE (CASE WHEN $2 = 'open' THEN g.affected_hosts > 0
                   ELSE g.affected_hosts = 0 AND g.previous_hosts > 0 END)
         AND g.q_match
         AND ($5::text[] IS NULL OR g.severity = ANY($5))
         AND (NOT $6::boolean OR g.is_kev)
         AND ($7::text[] IS NULL
              OR ('available' = ANY($7) AND g.any_fix)
              OR ('pro' = ANY($7) AND g.pro_only)
              OR ('none' = ANY($7) AND g.no_fix))
       ORDER BY ${orderBy}
       LIMIT $8 OFFSET $9
     )
     -- Refs, containers and versions for the page's image rows only.
     SELECT g.*, left(c.description, 200) AS description, im.refs, im.containers, im.image_fixes
     FROM page g
     LEFT JOIN cves c ON c.id = g.vuln_key
     LEFT JOIN LATERAL (
       WITH x AS (
         SELECT f.image_refs, f.container_names, f.source_package, f.installed_version,
                f.fixed_version
         FROM hosts h
         JOIN findings f ON f.host_id = h.id
         WHERE h.user_id = $1 AND h.archived_at IS NULL AND f.kind = 'vulnerable_image'
           AND f.vuln_key = g.vuln_key AND f.image_id = g.image_id AND f.image_os = g.image_os
           AND f.image_arch = g.image_arch AND f.image_variant = g.image_variant
           AND f.status = $2
       )
       SELECT ARRAY(SELECT DISTINCT r FROM x, unnest(x.image_refs) r ORDER BY r) AS refs,
              ARRAY(SELECT DISTINCT n FROM x, unnest(x.container_names) n ORDER BY n) AS containers,
              (SELECT json_agg(DISTINCT jsonb_build_object(
                        'sourcePackage', x.source_package,
                        'installedVersion', x.installed_version,
                        'fixedVersion', x.fixed_version))
               FROM x) AS image_fixes
     ) im ON g.is_image
     ORDER BY ${orderBy}`,
    [
      userId,
      f.status,
      findingKinds(f.kinds),
      f.q,
      f.severities,
      f.kev,
      f.fix,
      f.pageSize,
      (f.page - 1) * f.pageSize,
    ],
  );
  return { rows: rows.map(mapFleetRow), total: rows[0] ? Number(rows[0].total) : 0 };
}

// ---------------------------------------------------------------------------
// Per-kind counts for the fleet list header (never summed across kinds)
// ---------------------------------------------------------------------------

export type KindCounts = {
  vulns: number; // distinct vuln_keys with an open finding
  findings: number; // open findings
  hosts: number; // hosts with an open finding
  kev: number; // open KEV findings
  kevHosts: number;
  images: number; // image keys with an open finding (image kind only)
};

export type FleetVulnCounts = { hosts: number } & Record<VulnKind, KindCounts>;

export async function getFleetVulnCounts(userId: string): Promise<FleetVulnCounts> {
  const { rows } = await pool.query<{
    hosts: string;
    kind: string | null;
    vulns: string;
    findings: string;
    with_open: string;
    kev: string;
    kev_hosts: string;
    images: string;
  }>(
    `SELECT (SELECT count(*) FROM hosts WHERE user_id = $1 AND archived_at IS NULL) AS hosts,
            f.kind,
            count(DISTINCT f.vuln_key) AS vulns,
            count(f.id) AS findings,
            count(DISTINCT f.host_id) AS with_open,
            count(f.id) FILTER (WHERE f.is_kev) AS kev,
            count(DISTINCT f.host_id) FILTER (WHERE f.is_kev) AS kev_hosts,
            count(DISTINCT concat_ws('|', f.image_id, f.image_os, f.image_arch, f.image_variant))
              FILTER (WHERE f.image_id IS NOT NULL) AS images
     FROM hosts h
     LEFT JOIN findings f
       ON f.host_id = h.id AND f.status = 'open' AND f.vuln_key IS NOT NULL
      AND f.kind IN ('vulnerable_package', 'vulnerable_image')
     WHERE h.user_id = $1 AND h.archived_at IS NULL
     GROUP BY f.kind`,
    [userId],
  );
  const empty = (): KindCounts => ({
    vulns: 0,
    findings: 0,
    hosts: 0,
    kev: 0,
    kevHosts: 0,
    images: 0,
  });
  const out: FleetVulnCounts = {
    hosts: Number(rows[0]?.hosts ?? 0),
    package: empty(),
    image: empty(),
  };
  for (const r of rows) {
    if (r.kind === null) continue; // hosts without open findings
    const k: VulnKind = r.kind === FINDING_KIND.image ? "image" : "package";
    out[k] = {
      vulns: Number(r.vulns),
      findings: Number(r.findings),
      hosts: Number(r.with_open),
      kev: Number(r.kev),
      kevHosts: Number(r.kev_hosts),
      images: Number(r.images),
    };
  }
  return out;
}
