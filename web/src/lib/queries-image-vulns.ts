import { pool } from "./db";
import type { ImageKey } from "./image-key";
import type { ImageVulnFix, ImageVulnSort } from "./image-tables";
import { isSeverity, type Severity } from "./severity";

// The image detail page's Vulnerabilities tab: the rows of the image's
// effective package list (image_sbom_effective(user)) in image_sbom_vulns
// (migration 0018), one per (source package, vuln_key) exactly as
// store.ScoreImageSBOM grouped and assessed them (findings.BuildImage,
// severity.Assess): the web only displays, filters and sorts what Go
// wrote, so the rows add up to the image's score and a row's severity
// key equals its findings'. Works for images no container uses (score
// only, no findings). Where the user's hosts have vulnerable_image
// findings for a row, their lifecycle is attached.
//
// Rows are read only while the list's score is current (computed after
// the list was last written); until then the tab is empty and the page
// says matching is in progress.

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

// The user's effective list for the image key, while its score (and so
// its image_sbom_vulns rows) is current. $1..$5 = user, image key.
export const SCORED_LIST_SQL = `
  SELECT e.sbom_id
  FROM image_sbom_effective($1) e
  JOIN image_sbom_state st ON st.id = e.sbom_id
  JOIN image_sbom_scores sc ON sc.sbom_id = e.sbom_id AND sc.computed_at >= st.updated_at
  WHERE e.image_id = $2 AND e.os = $3 AND e.arch = $4 AND e.variant = $5`;

const VULNS_CTE = `
g AS (
  SELECT v.source_package AS source, v.vuln_key, v.ecosystem, v.installed_version AS version,
         v.fixed_version, v.fix_channel, v.fix_advisory_id, v.distro_severity, v.packages,
         v.advisory_ids, v.is_kev, v.epss_score, v.cvss_v3_score,
         left(c.description, 240) AS description, v.severity, v.severity_key
  FROM (${SCORED_LIST_SQL}) l
  JOIN image_sbom_vulns v ON v.sbom_id = l.sbom_id
  LEFT JOIN cves c ON c.id = v.vuln_key AND v.vuln_key LIKE 'CVE-%'
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
