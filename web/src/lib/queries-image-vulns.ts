import { pool } from "./db";
import type { ImageKey } from "./image-key";
import type { ImageVulnFix, ImageVulnSort } from "./image-tables";
import { isSeverity, type Severity } from "./severity";
import { severityLateral } from "./severity-sql";

// The image detail page's Vulnerabilities tab: the matches of the image's
// effective package list (software_vulnerabilities through
// image_sbom_effective(user) and image_software), one row per (source
// package, vuln_key) exactly as findings.BuildImage groups them, so it
// works for images no container uses (score only, no findings) and its
// rows add up to the image's score. Where the user's hosts have
// vulnerable_image findings for a row, their lifecycle is attached.
//
// Grouping as findings.group: rows without a match source are skipped, and
// so are kernel binaries (a container runs the host's kernel). The row
// that decides installed / fixed / fix channel / distro severity is the
// lowest installed source version; Go orders it with the ecosystem's
// comparator, here it is plain text order, which only differs when one
// source package's binaries come from different source versions (not seen
// in practice: a package set is built from one source upload).

export type ImageVulnRow = {
  vulnKey: string;
  sourcePackage: string;
  packages: string[];
  ecosystem: string;
  installedVersion: string;
  fixedVersion: string | null;
  fixChannel: string | null;
  fixAdvisoryId: string | null;
  advisoryIds: string[];
  distroSeverity: string | null;
  severity: Severity;
  isKev: boolean;
  epssScore: number | null;
  cvssV3Score: number | null;
  description: string | null;
  // vulnerable_image findings on the user's hosts for this row.
  findings: {
    hostId: string;
    hostname: string;
    label: string | null;
    status: "open" | "resolved";
    firstSeenAt: string;
    resolvedAt: string | null;
    reopenedAt: string | null;
  }[];
};

export type ImageVulnFilters = {
  q: string | null;
  severities: Severity[] | null;
  kev: boolean;
  fix: ImageVulnFix[] | null;
  sort: { id: ImageVulnSort; desc: boolean };
  page: number;
  pageSize: number;
};

// $1..$5 = user, image key.
const VULNS_CTE = `
m AS (
  SELECT sv.id AS software_id, sv.name, sv.ecosystem, sv.match_source AS source,
         sv.match_version AS version, sw.vuln_key, sw.fixed_version, sw.fix_channel,
         sw.fix_advisory_id, sw.advisory_ids, sw.distro_severity
  FROM image_sbom_effective($1) e
  JOIN image_software isw ON isw.sbom_id = e.sbom_id
  JOIN software_versions sv ON sv.id = isw.software_id
  JOIN software_vulnerabilities sw ON sw.software_id = sv.id
  WHERE e.image_id = $2 AND e.os = $3 AND e.arch = $4 AND e.variant = $5
    AND coalesce(sv.match_source, '') <> '' AND coalesce(sv.kernel_release, '') = ''
),
rep AS (
  SELECT DISTINCT ON (m.source, m.vuln_key) m.*
  FROM m
  ORDER BY m.source, m.vuln_key, m.version COLLATE "C", m.software_id
),
agg AS (
  SELECT m.source, m.vuln_key, array_agg(DISTINCT m.name ORDER BY m.name) AS packages,
         (SELECT array_agg(DISTINCT a ORDER BY a)
          FROM m m2, unnest(m2.advisory_ids) a
          WHERE m2.source = m.source AND m2.vuln_key = m.vuln_key) AS advisory_ids
  FROM m
  GROUP BY m.source, m.vuln_key
),
g AS (
  SELECT rep.source, rep.vuln_key, rep.ecosystem, rep.version, rep.fixed_version,
         rep.fix_channel, rep.fix_advisory_id, rep.distro_severity, agg.packages,
         coalesce(agg.advisory_ids, '{}') AS advisory_ids,
         coalesce(c.is_kev, false) AS is_kev, c.epss_score, c.cvss_v3_score,
         left(c.description, 240) AS description, sev.bucket, sev.severity, sev.severity_key
  FROM rep
  JOIN agg ON agg.source = rep.source AND agg.vuln_key = rep.vuln_key
  LEFT JOIN cves c ON c.id = rep.vuln_key AND rep.vuln_key LIKE 'CVE-%'
  ${severityLateral("sev", {
    distroSeverity: "rep.distro_severity",
    fixChannel: "rep.fix_channel",
    kev: "c.is_kev",
    epss: "c.epss_score",
    cvss: "c.cvss_v3_score",
  })}
)`;

export async function getImageVulns(
  workspaceId: string,
  key: ImageKey,
  f: ImageVulnFilters,
): Promise<{ rows: ImageVulnRow[]; total: number }> {
  const dir = f.sort.desc ? "DESC" : "ASC";
  const nulls = f.sort.desc ? "NULLS LAST" : "NULLS FIRST";
  const orderBy = {
    severity: `g.severity_key ${dir}, g.vuln_key, g.source`,
    vuln: `g.vuln_key ${dir}, g.source`,
    package: `g.source ${dir}, g.severity_key DESC, g.vuln_key`,
    epss: `g.epss_score ${dir} ${nulls}, g.severity_key DESC, g.vuln_key`,
    cvss: `g.cvss_v3_score ${dir} ${nulls}, g.severity_key DESC, g.vuln_key`,
  }[f.sort.id];
  const { rows } = await pool.query<{
    source: string;
    vuln_key: string;
    ecosystem: string;
    version: string;
    fixed_version: string | null;
    fix_channel: string | null;
    fix_advisory_id: string | null;
    distro_severity: string | null;
    packages: string[];
    advisory_ids: string[];
    is_kev: boolean;
    epss_score: string | null;
    cvss_v3_score: string | null;
    description: string | null;
    severity: string;
    findings: ImageVulnRow["findings"] | null;
    total: string;
  }>(
    `WITH ${VULNS_CTE}
     SELECT g.*, fl.findings, count(*) OVER () AS total
     FROM g
     LEFT JOIN LATERAL (
       SELECT json_agg(json_build_object(
                'hostId', h.id, 'hostname', h.hostname, 'label', h.label, 'status', f.status,
                'firstSeenAt', f.first_seen_at, 'resolvedAt', f.resolved_at,
                'reopenedAt', f.reopened_at)
              ORDER BY f.status = 'open' DESC, lower(coalesce(h.label, h.hostname))) AS findings
       FROM findings f
       JOIN hosts h ON h.id = f.host_id AND h.workspace_id = $1
       WHERE f.kind = 'vulnerable_image' AND f.image_id = $2 AND f.image_os = $3
         AND f.image_arch = $4 AND f.image_variant = $5
         AND f.source_package = g.source AND f.vuln_key = g.vuln_key
     ) fl ON true
     WHERE ($6::text IS NULL
            OR strpos(lower(g.vuln_key), lower($6)) > 0
            OR strpos(lower(g.source), lower($6)) > 0
            OR EXISTS (SELECT 1 FROM unnest(g.packages) p WHERE strpos(lower(p), lower($6)) > 0))
       AND ($7::text[] IS NULL OR g.severity = ANY($7))
       AND (NOT $8::boolean OR g.is_kev)
       AND ($9::text[] IS NULL
            OR ('available' = ANY($9) AND g.fix_channel = 'standard')
            OR ('pro' = ANY($9) AND g.fix_channel = 'ubuntu-pro')
            OR ('none' = ANY($9) AND g.fixed_version IS NULL))
     ORDER BY ${orderBy}
     LIMIT $10 OFFSET $11`,
    [
      workspaceId,
      key.imageId,
      key.os,
      key.arch,
      key.variant,
      f.q,
      f.severities,
      f.kev,
      f.fix,
      f.pageSize,
      (f.page - 1) * f.pageSize,
    ],
  );
  return {
    rows: rows.map((r) => ({
      vulnKey: r.vuln_key,
      sourcePackage: r.source,
      packages: r.packages,
      ecosystem: r.ecosystem,
      installedVersion: r.version,
      fixedVersion: r.fixed_version,
      fixChannel: r.fix_channel,
      fixAdvisoryId: r.fix_advisory_id,
      advisoryIds: r.advisory_ids,
      distroSeverity: r.distro_severity,
      severity: isSeverity(r.severity) ? r.severity : "unknown",
      isKev: r.is_kev,
      epssScore: r.epss_score === null ? null : Number(r.epss_score),
      cvssV3Score: r.cvss_v3_score === null ? null : Number(r.cvss_v3_score),
      description: r.description,
      findings: r.findings ?? [],
    })),
    total: rows[0] ? Number(rows[0].total) : 0,
  };
}
