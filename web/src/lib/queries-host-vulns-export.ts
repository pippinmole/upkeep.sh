import { pool } from "./db";
import type { HostVulnFilters } from "./host-vulns-filters";
import { isUuid } from "./queries-inventory";

// Every finding on one host's Vulnerabilities tab for the CSV export: the
// same WHERE and ORDER BY as getHostFindings (queries-vulns.ts), without
// LIMIT/OFFSET, plus the CVE and advisory fields a spreadsheet wants.
//
// Tenancy as in queries-vulns.ts: the read starts from
// `hosts h WHERE h.id = $2 AND h.user_id = $1`, so another user's host
// yields no rows. cves and advisories are public feed data, reached only
// through this host's findings.

export type ExportFindingRow = {
  vulnKey: string;
  // Other ids for the same vulnerability: aliases and CVE ids of the
  // finding's advisories that are about this vuln_key (e.g. UBUNTU-CVE-*).
  // A bundle notice such as a USN names many CVEs, so it isn't used here.
  aliases: string[];
  advisoryIds: string[];
  status: string;
  severity: string | null;
  distroSeverity: string | null;
  cvssV3Score: number | null;
  cvssV3Vector: string | null;
  epssScore: number | null;
  epssPercentile: number | null;
  isKev: boolean;
  kevAddedAt: string | null; // YYYY-MM-DD
  kevDueDate: string | null; // YYYY-MM-DD
  sourcePackage: string | null;
  packages: string[];
  installedVersion: string | null;
  fixedVersion: string | null;
  fixChannel: string | null;
  requiresPro: boolean;
  fixAdvisoryId: string | null;
  kernelRelease: string | null;
  runningKernelUnknown: boolean;
  publishedAt: string | null; // earliest publication among the finding's advisories
  firstSeenAt: string;
  reopenedAt: string | null;
  reopenCount: number;
  resolvedAt: string | null;
  description: string | null;
};

type DbRow = {
  vuln_key: string;
  aliases: string[];
  advisory_ids: string[];
  status: string;
  severity: string | null;
  distro_severity: string | null;
  cvss_v3_score: string | null;
  cvss_v3_vector: string | null;
  epss_score: string | null;
  epss_percentile: string | null;
  is_kev: boolean;
  kev_added_at: string | null;
  kev_due_date: string | null;
  source_package: string | null;
  packages: string[];
  installed_version: string | null;
  fixed_version: string | null;
  fix_channel: string | null;
  requires_pro: boolean;
  fix_advisory_id: string | null;
  kernel_release: string | null;
  running_kernel_unknown: boolean;
  published_at: Date | null;
  first_seen_at: Date;
  reopened_at: Date | null;
  reopen_count: number;
  resolved_at: Date | null;
  description: string | null;
};

const num = (v: string | null): number | null => (v === null ? null : Number(v));
const iso = (d: Date | null): string | null => d?.toISOString() ?? null;

export async function getHostFindingsForExport(
  userId: string,
  hostId: string,
  f: HostVulnFilters,
): Promise<ExportFindingRow[]> {
  if (!isUuid(hostId)) return [];
  const orderBy =
    f.status === "resolved"
      ? "f.resolved_at DESC, f.vuln_key"
      : f.sort === "recent"
        ? "f.first_seen_at DESC, f.severity_key DESC, f.vuln_key"
        : "f.severity_key DESC, f.vuln_key";
  const { rows } = await pool.query<DbRow>(
    `SELECT f.vuln_key, coalesce(a.aliases, '{}') AS aliases, f.advisory_ids,
            f.status, f.severity, f.distro_severity,
            f.cvss_v3_score, c.cvss_v3_vector,
            f.epss_score, f.epss_percentile, f.is_kev,
            c.kev_added_at::text, c.kev_due_date::text,
            f.source_package, f.packages, f.installed_version, f.fixed_version,
            f.fix_channel, f.requires_pro, f.fix_advisory_id, f.kernel_release,
            f.running_kernel_unknown, a.published_at, f.first_seen_at,
            f.reopened_at, f.reopen_count, f.resolved_at, c.description
     FROM hosts h
     JOIN findings f ON f.host_id = h.id
     LEFT JOIN cves c ON c.id = f.vuln_key
     LEFT JOIN LATERAL (
       SELECT min(a.published_at) AS published_at,
              array(SELECT DISTINCT x
                    FROM advisories a2, unnest(a2.cve_ids || a2.aliases) x
                    WHERE a2.id = ANY(f.advisory_ids) AND a2.vuln_key = f.vuln_key
                      AND x <> f.vuln_key
                    ORDER BY x) AS aliases
       FROM advisories a
       WHERE a.id = ANY(f.advisory_ids)
     ) a ON true
     WHERE h.id = $2 AND h.user_id = $1
       AND f.kind = 'vulnerable_package' AND f.status = $3
       AND ($4::text IS NULL
            OR strpos(lower(f.vuln_key), lower($4)) > 0
            OR strpos(lower(coalesce(f.source_package, '')), lower($4)) > 0
            OR EXISTS (SELECT 1 FROM unnest(f.packages) p WHERE strpos(lower(p), lower($4)) > 0))
       AND ($5::text IS NULL OR f.severity = $5)
       AND (NOT $6::boolean OR f.is_kev)
       AND ($7::text IS NULL
            OR ($7 = 'available' AND f.fix_channel = 'standard')
            OR ($7 = 'pro' AND f.requires_pro)
            OR ($7 = 'none' AND f.fixed_version IS NULL))
     ORDER BY ${orderBy}`,
    [userId, hostId, f.status, f.q, f.severity, f.kev, f.fix],
  );
  return rows.map((r) => ({
    vulnKey: r.vuln_key,
    aliases: r.aliases,
    advisoryIds: r.advisory_ids,
    status: r.status,
    severity: r.severity,
    distroSeverity: r.distro_severity,
    cvssV3Score: num(r.cvss_v3_score),
    cvssV3Vector: r.cvss_v3_vector,
    epssScore: num(r.epss_score),
    epssPercentile: num(r.epss_percentile),
    isKev: r.is_kev,
    kevAddedAt: r.kev_added_at,
    kevDueDate: r.kev_due_date,
    sourcePackage: r.source_package,
    packages: r.packages,
    installedVersion: r.installed_version,
    fixedVersion: r.fixed_version,
    fixChannel: r.fix_channel,
    requiresPro: r.requires_pro,
    fixAdvisoryId: r.fix_advisory_id,
    kernelRelease: r.kernel_release,
    runningKernelUnknown: r.running_kernel_unknown,
    publishedAt: iso(r.published_at),
    firstSeenAt: r.first_seen_at.toISOString(),
    reopenedAt: iso(r.reopened_at),
    reopenCount: r.reopen_count,
    resolvedAt: iso(r.resolved_at),
    description: r.description,
  }));
}
