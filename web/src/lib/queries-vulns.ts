import { cache } from "react";

import { pool } from "./db";
import { isUuid } from "./queries-inventory";
import { emptySeverityCounts, isSeverity, type Severity, type SeverityCounts } from "./severity";

// Vulnerability reads (DOMAIN_MODEL.md §3.3, §3.5, §3.6). Sources, per the
// P1b backend (migration 0007, ARCHITECTURE.md "Vulnerability pipeline"):
//   findings (kind 'vulnerable_package')  per-host open/resolved state, with
//                                          severity/fix/KEV/EPSS snapshotted
//   host_package_vuln_status (view)       per (host, binary) open summary
//   host_kernel_packages (view)           installed kernels, is_running
//   software_vulnerabilities              positive matches per interned version
//   cves, advisories, advisory_affected   public advisory data
//
// Tenancy: findings are per host, so every findings read starts from
// `hosts h WHERE h.user_id = $1`. software_vulnerabilities and
// software_versions are shared ACROSS USERS: they are only reached through
// the user's own host_software or findings rows, never by an id taken from
// the URL on its own. cves / advisories / advisory_affected are public
// feed data and may be shown to anyone signed in.

const num = (v: string | null): number | null => (v === null ? null : Number(v));
const iso = (d: Date | null): string | null => d?.toISOString() ?? null;

// ---------------------------------------------------------------------------
// Summary counts (host header, host list, overview)
// ---------------------------------------------------------------------------

export type VulnSummary = {
  open: number; // open vulnerable_package findings
  resolved: number;
  kev: number;
  bySeverity: SeverityCounts;
  topSeverity: Severity | null;
  fixable: number; // fix in the standard archive
  proOnly: number; // only fix is Ubuntu Pro
  unfixed: number; // no fix published
  // Open findings raised while the running kernel was unknown (every
  // installed kernel counted).
  runningKernelUnknown: number;
};

type SummaryRow = {
  severity: string | null;
  open: string;
  resolved: string;
  kev: string;
  fixable: string;
  pro_only: string;
  unfixed: string;
  rk_unknown: string;
};

const SUMMARY_COLUMNS = `
  f.severity,
  count(*) FILTER (WHERE f.status = 'open')                                   AS open,
  count(*) FILTER (WHERE f.status = 'resolved')                               AS resolved,
  count(*) FILTER (WHERE f.status = 'open' AND f.is_kev)                      AS kev,
  count(*) FILTER (WHERE f.status = 'open' AND f.fix_channel = 'standard')    AS fixable,
  count(*) FILTER (WHERE f.status = 'open' AND f.requires_pro)                AS pro_only,
  count(*) FILTER (WHERE f.status = 'open' AND f.fixed_version IS NULL)       AS unfixed,
  count(*) FILTER (WHERE f.status = 'open' AND f.running_kernel_unknown)      AS rk_unknown`;

function foldSummary(rows: SummaryRow[]): VulnSummary {
  const s: VulnSummary = {
    open: 0,
    resolved: 0,
    kev: 0,
    bySeverity: emptySeverityCounts(),
    topSeverity: null,
    fixable: 0,
    proOnly: 0,
    unfixed: 0,
    runningKernelUnknown: 0,
  };
  for (const r of rows) {
    const open = Number(r.open);
    s.open += open;
    s.resolved += Number(r.resolved);
    s.kev += Number(r.kev);
    s.fixable += Number(r.fixable);
    s.proOnly += Number(r.pro_only);
    s.unfixed += Number(r.unfixed);
    s.runningKernelUnknown += Number(r.rk_unknown);
    const sev: Severity = isSeverity(r.severity) ? r.severity : "unknown";
    s.bySeverity[sev] += open;
  }
  for (const sev of Object.keys(s.bySeverity) as Severity[]) {
    if (s.bySeverity[sev] > 0) {
      s.topSeverity = sev;
      break;
    }
  }
  return s;
}

// Host header + tabs share this per request (React cache).
export const getHostVulnSummary = cache(async function getHostVulnSummary(
  userId: string,
  hostId: string,
): Promise<VulnSummary> {
  if (!isUuid(hostId)) return foldSummary([]);
  const { rows } = await pool.query<SummaryRow>(
    `SELECT ${SUMMARY_COLUMNS}
     FROM hosts h
     JOIN findings f ON f.host_id = h.id AND f.kind = 'vulnerable_package'
     WHERE h.id = $2 AND h.user_id = $1
     GROUP BY f.severity`,
    [userId, hostId],
  );
  return foldSummary(rows);
});

export type OverviewStats = {
  hosts: number;
  staleHosts: number; // not seen in 24h (or never)
  hostsWithOpen: number;
  hostsWithKev: number;
  rebootPending: number;
  vulns: VulnSummary;
  distinctOpenVulns: number;
};

export async function getOverviewStats(userId: string): Promise<OverviewStats> {
  const [hosts, sev] = await Promise.all([
    pool.query<{
      hosts: string;
      stale: string;
      with_open: string;
      with_kev: string;
      reboot: string;
      distinct_vulns: string;
    }>(
      `SELECT count(*) AS hosts,
              count(*) FILTER (WHERE h.last_seen_at IS NULL
                                  OR h.last_seen_at < now() - interval '24 hours') AS stale,
              count(*) FILTER (WHERE fc.open > 0) AS with_open,
              count(*) FILTER (WHERE fc.kev > 0)  AS with_kev,
              count(*) FILTER (WHERE s.reboot_required) AS reboot,
              (SELECT count(DISTINCT f.vuln_key)
               FROM hosts h2
               JOIN findings f ON f.host_id = h2.id
               WHERE h2.user_id = $1 AND f.kind = 'vulnerable_package'
                 AND f.status = 'open') AS distinct_vulns
       FROM hosts h
       LEFT JOIN LATERAL (
         SELECT s.reboot_required FROM snapshots s
         WHERE s.host_id = h.id
         ORDER BY s.collected_at DESC LIMIT 1   -- snapshots_host_collected_idx
       ) s ON true
       LEFT JOIN LATERAL (
         SELECT count(*) AS open, count(*) FILTER (WHERE f.is_kev) AS kev
         FROM findings f
         WHERE f.host_id = h.id AND f.status = 'open' AND f.kind = 'vulnerable_package'
       ) fc ON true
       WHERE h.user_id = $1`,
      [userId],
    ),
    pool.query<SummaryRow>(
      `SELECT ${SUMMARY_COLUMNS}
       FROM hosts h
       JOIN findings f ON f.host_id = h.id AND f.kind = 'vulnerable_package'
       WHERE h.user_id = $1
       GROUP BY f.severity`,
      [userId],
    ),
  ]);
  const h = hosts.rows[0];
  return {
    hosts: Number(h.hosts),
    staleHosts: Number(h.stale),
    hostsWithOpen: Number(h.with_open),
    hostsWithKev: Number(h.with_kev),
    rebootPending: Number(h.reboot),
    distinctOpenVulns: Number(h.distinct_vulns),
    vulns: foldSummary(sev.rows),
  };
}

// ---------------------------------------------------------------------------
// Per-host vulnerabilities tab
// ---------------------------------------------------------------------------

export type FindingRow = {
  vulnKey: string;
  sourcePackage: string | null;
  packages: string[];
  installedVersion: string | null;
  fixedVersion: string | null;
  fixChannel: string | null;
  requiresPro: boolean;
  severity: string | null;
  isKev: boolean;
  epssScore: number | null;
  epssPercentile: number | null;
  cvssV3Score: number | null;
  distroSeverity: string | null;
  advisoryIds: string[];
  fixAdvisoryId: string | null;
  firstSeenAt: string;
  resolvedAt: string | null;
  reopenedAt: string | null;
  reopenCount: number;
  runningKernelUnknown: boolean;
  kernelRelease: string | null;
  description: string | null; // cves.description, truncated
};

type FindingDbRow = {
  vuln_key: string;
  source_package: string | null;
  packages: string[];
  installed_version: string | null;
  fixed_version: string | null;
  fix_channel: string | null;
  requires_pro: boolean;
  severity: string | null;
  is_kev: boolean;
  epss_score: string | null;
  epss_percentile: string | null;
  cvss_v3_score: string | null;
  distro_severity: string | null;
  advisory_ids: string[];
  fix_advisory_id: string | null;
  first_seen_at: Date;
  resolved_at: Date | null;
  reopened_at: Date | null;
  reopen_count: number;
  running_kernel_unknown: boolean;
  kernel_release: string | null;
  description: string | null;
};

const FINDING_COLUMNS = `
  f.vuln_key, f.source_package, f.packages, f.installed_version,
  f.fixed_version, f.fix_channel, f.requires_pro, f.severity, f.is_kev,
  f.epss_score, f.epss_percentile, f.cvss_v3_score, f.distro_severity,
  f.advisory_ids, f.fix_advisory_id, f.first_seen_at, f.resolved_at,
  f.reopened_at, f.reopen_count, f.running_kernel_unknown, f.kernel_release`;

function mapFinding(r: FindingDbRow): FindingRow {
  return {
    vulnKey: r.vuln_key,
    sourcePackage: r.source_package,
    packages: r.packages,
    installedVersion: r.installed_version,
    fixedVersion: r.fixed_version,
    fixChannel: r.fix_channel,
    requiresPro: r.requires_pro,
    severity: r.severity,
    isKev: r.is_kev,
    epssScore: num(r.epss_score),
    epssPercentile: num(r.epss_percentile),
    cvssV3Score: num(r.cvss_v3_score),
    distroSeverity: r.distro_severity,
    advisoryIds: r.advisory_ids,
    fixAdvisoryId: r.fix_advisory_id,
    firstSeenAt: r.first_seen_at.toISOString(),
    resolvedAt: iso(r.resolved_at),
    reopenedAt: iso(r.reopened_at),
    reopenCount: r.reopen_count,
    runningKernelUnknown: r.running_kernel_unknown,
    kernelRelease: r.kernel_release,
    description: r.description,
  };
}

export type FixFilter = "available" | "pro" | "none";

export type HostFindingFilters = {
  status: "open" | "resolved";
  q: string | null; // vuln key, source or binary package substring
  severity: Severity | null;
  kev: boolean;
  fix: FixFilter | null;
  sort: "severity" | "recent";
  page: number;
  pageSize: number;
};

export async function getHostFindings(
  userId: string,
  hostId: string,
  f: HostFindingFilters,
): Promise<{ rows: FindingRow[]; total: number }> {
  if (!isUuid(hostId)) return { rows: [], total: 0 };
  // Static ORDER BY variants; the open + severity form walks
  // findings_host_open_rank_idx.
  const orderBy =
    f.status === "resolved"
      ? "f.resolved_at DESC, f.vuln_key"
      : f.sort === "recent"
        ? "f.first_seen_at DESC, f.severity_key DESC, f.vuln_key"
        : "f.severity_key DESC, f.vuln_key";
  const { rows } = await pool.query<FindingDbRow & { total: string }>(
    `SELECT ${FINDING_COLUMNS}, left(c.description, 240) AS description,
            count(*) OVER () AS total
     FROM hosts h
     JOIN findings f ON f.host_id = h.id
     LEFT JOIN cves c ON c.id = f.vuln_key
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
     ORDER BY ${orderBy}
     LIMIT $8 OFFSET $9`,
    [
      userId,
      hostId,
      f.status,
      f.q,
      f.severity,
      f.kev,
      f.fix,
      f.pageSize,
      (f.page - 1) * f.pageSize,
    ],
  );
  return { rows: rows.map(mapFinding), total: rows[0] ? Number(rows[0].total) : 0 };
}

export type CveDetail = {
  id: string;
  description: string | null;
  cvssV3Score: number | null;
  cvssV3Vector: string | null;
  epssScore: number | null;
  epssPercentile: number | null;
  epssDate: string | null;
  isKev: boolean;
  kevAddedAt: string | null;
  kevDueDate: string | null;
  kevRansomware: boolean | null;
};

export type AdvisoryDetail = {
  id: string;
  source: string;
  vulnKey: string;
  cveIds: string[];
  summary: string | null;
  details: string | null;
  severity: string | null;
  publishedAt: string | null;
  modifiedAt: string;
  withdrawnAt: string | null;
};

// cves / advisories are public feed data: no tenancy predicate needed.
async function getCve(vulnKey: string): Promise<CveDetail | null> {
  const { rows } = await pool.query<{
    id: string;
    description: string | null;
    cvss_v3_score: string | null;
    cvss_v3_vector: string | null;
    epss_score: string | null;
    epss_percentile: string | null;
    epss_date: string | null;
    is_kev: boolean;
    kev_added_at: string | null;
    kev_due_date: string | null;
    kev_ransomware: boolean | null;
  }>(
    `SELECT id, description, cvss_v3_score, cvss_v3_vector, epss_score,
            epss_percentile, epss_date::text, is_kev, kev_added_at::text,
            kev_due_date::text, kev_ransomware
     FROM cves WHERE id = $1`,
    [vulnKey],
  );
  const r = rows[0];
  if (!r) return null;
  return {
    id: r.id,
    description: r.description,
    cvssV3Score: num(r.cvss_v3_score),
    cvssV3Vector: r.cvss_v3_vector,
    epssScore: num(r.epss_score),
    epssPercentile: num(r.epss_percentile),
    epssDate: r.epss_date,
    isKev: r.is_kev,
    kevAddedAt: r.kev_added_at,
    kevDueDate: r.kev_due_date,
    kevRansomware: r.kev_ransomware,
  };
}

type AdvisoryDbRow = {
  id: string;
  source: string;
  vuln_key: string;
  cve_ids: string[];
  summary: string | null;
  details: string | null;
  severity: string | null;
  published_at: Date | null;
  modified_at: Date;
  withdrawn_at: Date | null;
};

const ADVISORY_COLUMNS = `a.id, a.source, a.vuln_key, a.cve_ids, a.summary, a.details,
  a.severity, a.published_at, a.modified_at, a.withdrawn_at`;

function mapAdvisory(r: AdvisoryDbRow): AdvisoryDetail {
  return {
    id: r.id,
    source: r.source,
    vulnKey: r.vuln_key,
    cveIds: r.cve_ids,
    summary: r.summary,
    details: r.details,
    severity: r.severity,
    publishedAt: iso(r.published_at),
    modifiedAt: r.modified_at.toISOString(),
    withdrawnAt: iso(r.withdrawn_at),
  };
}

export type HostFindingDetail = {
  findings: FindingRow[]; // one per source package (open first)
  cve: CveDetail | null;
  advisories: AdvisoryDetail[];
};

// Sheet on the host Vulnerabilities tab (?v=<vuln_key>). Null when this
// host (owned by userId) has no finding for vulnKey.
export async function getHostFindingDetail(
  userId: string,
  hostId: string,
  vulnKey: string,
): Promise<HostFindingDetail | null> {
  if (!isUuid(hostId)) return null;
  const { rows } = await pool.query<FindingDbRow>(
    `SELECT ${FINDING_COLUMNS}, NULL::text AS description
     FROM hosts h
     JOIN findings f ON f.host_id = h.id
     WHERE h.id = $2 AND h.user_id = $1
       AND f.kind = 'vulnerable_package' AND f.vuln_key = $3
     ORDER BY f.status, f.source_package`,
    [userId, hostId, vulnKey],
  );
  if (rows.length === 0) return null;
  const ids = [...new Set(rows.flatMap((r) => r.advisory_ids))];
  const [cve, adv] = await Promise.all([
    getCve(vulnKey),
    pool.query<AdvisoryDbRow>(
      `SELECT ${ADVISORY_COLUMNS} FROM advisories a WHERE a.id = ANY($1::text[])
       ORDER BY a.source, a.id`,
      [ids],
    ),
  ]);
  return { findings: rows.map(mapFinding), cve, advisories: adv.rows.map(mapAdvisory) };
}

export type KernelPackage = {
  softwareId: string;
  name: string;
  version: string;
  arch: string;
  sourcePackage: string | null;
  kernelRelease: string;
  isRunning: boolean | null; // null = running kernel unknown
  firstSeenAt: string;
  vulnCount: number;
  fixableCount: number;
};

export async function getHostKernels(userId: string, hostId: string): Promise<KernelPackage[]> {
  if (!isUuid(hostId)) return [];
  const { rows } = await pool.query<{
    software_id: string;
    name: string;
    version: string;
    arch: string;
    source_package: string | null;
    kernel_release: string;
    is_running: boolean | null;
    first_seen_at: Date;
    vuln_count: string;
    fixable_count: string;
  }>(
    `SELECT k.software_id, k.name, k.version, k.arch, k.source_package,
            k.kernel_release, k.is_running, k.first_seen_at, k.vuln_count,
            k.fixable_count
     FROM hosts h
     JOIN host_kernel_packages k ON k.host_id = h.id
     WHERE h.id = $2 AND h.user_id = $1
     ORDER BY k.is_running DESC NULLS LAST, k.kernel_release DESC, k.name`,
    [userId, hostId],
  );
  return rows.map((r) => ({
    softwareId: r.software_id,
    name: r.name,
    version: r.version,
    arch: r.arch,
    sourcePackage: r.source_package,
    kernelRelease: r.kernel_release,
    isRunning: r.is_running,
    firstSeenAt: r.first_seen_at.toISOString(),
    vulnCount: Number(r.vuln_count),
    fixableCount: Number(r.fixable_count),
  }));
}

// ---------------------------------------------------------------------------
// Packages tab: one package's vulnerabilities (row sheet)
// ---------------------------------------------------------------------------

export type PackageVulnSheet = {
  pkg: {
    softwareId: string;
    name: string;
    version: string;
    arch: string;
    sourceName: string | null;
    sourceVersion: string | null;
    matchSource: string | null;
    kernelRelease: string | null;
    maxFixedVersion: string | null;
    installed: boolean; // has an open range on this host
  };
  vulns: {
    vulnKey: string;
    fixedVersion: string | null;
    fixChannel: string | null;
    distroSeverity: string | null;
    advisoryIds: string[];
    // From this host's open finding; null = no open finding (e.g. a
    // kernel that isn't the running one).
    severity: string | null;
    hasFinding: boolean;
    isKev: boolean;
    epssScore: number | null;
    cvssV3Score: number | null;
    description: string | null;
  }[];
};

// softwareId comes from the URL (?pkg=). It is only honoured when this
// host (owned by userId) has, or had, that version installed.
export async function getPackageVulns(
  userId: string,
  hostId: string,
  softwareId: string,
): Promise<PackageVulnSheet | null> {
  if (!isUuid(hostId) || !/^\d{1,18}$/.test(softwareId)) return null;
  const pkg = await pool.query<{
    software_id: string;
    name: string;
    version: string;
    arch: string;
    source_name: string | null;
    source_version: string | null;
    match_source: string | null;
    kernel_release: string | null;
    max_fixed_version: string | null;
    installed: boolean;
  }>(
    `SELECT sv.id AS software_id, sv.name, sv.version, sv.arch, sv.source_name,
            sv.source_version, sv.match_source, sv.kernel_release,
            sv.max_fixed_version, bool_or(hs.removed_at IS NULL) AS installed
     FROM hosts h
     JOIN host_software hs ON hs.host_id = h.id
     JOIN software_versions sv ON sv.id = hs.software_id
     WHERE h.id = $2 AND h.user_id = $1 AND hs.software_id = $3::bigint
     GROUP BY sv.id`,
    [userId, hostId, softwareId],
  );
  const p = pkg.rows[0];
  if (!p) return null;

  // The EXISTS repeats the ownership check so this statement is safe on
  // its own, not only after the query above.
  const { rows } = await pool.query<{
    vuln_key: string;
    fixed_version: string | null;
    fix_channel: string | null;
    distro_severity: string | null;
    advisory_ids: string[];
    severity: string | null;
    has_finding: boolean;
    is_kev: boolean | null;
    epss_score: string | null;
    cvss_v3_score: string | null;
    description: string | null;
  }>(
    `SELECT sw.vuln_key, sw.fixed_version, sw.fix_channel, sw.distro_severity,
            sw.advisory_ids, f.severity, f.vuln_key IS NOT NULL AS has_finding,
            coalesce(f.is_kev, c.is_kev) AS is_kev,
            coalesce(f.epss_score, c.epss_score) AS epss_score,
            coalesce(f.cvss_v3_score, c.cvss_v3_score) AS cvss_v3_score,
            left(c.description, 240) AS description
     FROM software_vulnerabilities sw
     LEFT JOIN findings f
       ON f.host_id = $2 AND f.kind = 'vulnerable_package' AND f.status = 'open'
      AND f.vuln_key = sw.vuln_key AND $3::bigint = ANY (f.software_ids)
     LEFT JOIN cves c ON c.id = sw.vuln_key
     WHERE sw.software_id = $3::bigint
       AND EXISTS (SELECT 1 FROM hosts h
                   JOIN host_software hs ON hs.host_id = h.id
                   WHERE h.id = $2 AND h.user_id = $1 AND hs.software_id = $3::bigint)
     ORDER BY f.severity_key DESC NULLS LAST, c.is_kev DESC NULLS LAST,
              c.epss_score DESC NULLS LAST, sw.vuln_key`,
    [userId, hostId, softwareId],
  );
  return {
    pkg: {
      softwareId: p.software_id,
      name: p.name,
      version: p.version,
      arch: p.arch,
      sourceName: p.source_name,
      sourceVersion: p.source_version,
      matchSource: p.match_source,
      kernelRelease: p.kernel_release,
      maxFixedVersion: p.max_fixed_version,
      installed: p.installed,
    },
    vulns: rows.map((r) => ({
      vulnKey: r.vuln_key,
      fixedVersion: r.fixed_version,
      fixChannel: r.fix_channel,
      distroSeverity: r.distro_severity,
      advisoryIds: r.advisory_ids,
      severity: r.severity,
      hasFinding: r.has_finding,
      isKev: r.is_kev ?? false,
      epssScore: num(r.epss_score),
      cvssV3Score: num(r.cvss_v3_score),
      description: r.description,
    })),
  };
}

// ---------------------------------------------------------------------------
// History tab: security effect of each paired change
// ---------------------------------------------------------------------------

export type ChangeEffect = { fixed: number; fixedKev: number; introduced: number };

// For each (old software_id -> new software_id) change on this host:
// fixed = vuln_keys matched for the old version but not the new one;
// introduced = the reverse. Based on current advisory knowledge
// (software_vulnerabilities as of now), not what was known at the time.
// Pairs are kept only if both versions are in this host's history.
export async function getChangeEffects(
  userId: string,
  hostId: string,
  pairs: { from: string; to: string }[],
): Promise<Map<string, ChangeEffect>> {
  const out = new Map<string, ChangeEffect>();
  if (!isUuid(hostId) || pairs.length === 0) return out;
  const { rows } = await pool.query<{
    old_id: string;
    new_id: string;
    fixed: string;
    fixed_kev: string;
    introduced: string;
  }>(
    `WITH owned AS (SELECT id FROM hosts WHERE id = $2 AND user_id = $1),
     pairs AS (
       SELECT DISTINCT p.old_id, p.new_id
       FROM unnest($3::bigint[], $4::bigint[]) AS p(old_id, new_id)
       WHERE EXISTS (SELECT 1 FROM host_software hs JOIN owned ON hs.host_id = owned.id
                     WHERE hs.software_id = p.old_id)
         AND EXISTS (SELECT 1 FROM host_software hs JOIN owned ON hs.host_id = owned.id
                     WHERE hs.software_id = p.new_id)
     )
     SELECT p.old_id, p.new_id, fx.fixed, fx.fixed_kev, intro.introduced
     FROM pairs p
     CROSS JOIN LATERAL (
       SELECT count(*) AS fixed, count(*) FILTER (WHERE c.is_kev) AS fixed_kev
       FROM (SELECT vuln_key FROM software_vulnerabilities WHERE software_id = p.old_id
             EXCEPT
             SELECT vuln_key FROM software_vulnerabilities WHERE software_id = p.new_id) d
       LEFT JOIN cves c ON c.id = d.vuln_key
     ) fx
     CROSS JOIN LATERAL (
       SELECT count(*) AS introduced
       FROM (SELECT vuln_key FROM software_vulnerabilities WHERE software_id = p.new_id
             EXCEPT
             SELECT vuln_key FROM software_vulnerabilities WHERE software_id = p.old_id) d
     ) intro`,
    [userId, hostId, pairs.map((p) => p.from), pairs.map((p) => p.to)],
  );
  for (const r of rows) {
    out.set(`${r.old_id}>${r.new_id}`, {
      fixed: Number(r.fixed),
      fixedKev: Number(r.fixed_kev),
      introduced: Number(r.introduced),
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Fleet vulnerabilities
// ---------------------------------------------------------------------------

export type FleetVulnRow = {
  vulnKey: string;
  severity: string | null;
  isKev: boolean;
  epssScore: number | null;
  cvssV3Score: number | null;
  affectedHosts: number; // hosts with an open finding
  previousHosts: number; // hosts with a resolved finding only
  packages: string[]; // source packages
  anyFix: boolean; // a standard-archive fix exists for some affected host
  proOnly: boolean; // some affected host's only fix is Ubuntu Pro
  noFix: boolean; // some affected host has no fix at all
  firstSeenAt: string;
  description: string | null;
};

export type FleetVulnFilters = {
  status: "open" | "resolved";
  q: string | null;
  severity: Severity | null;
  kev: boolean;
  fix: FixFilter | null;
  sort: "severity" | "hosts" | "recent";
  page: number;
  pageSize: number;
};

export async function getFleetVulns(
  userId: string,
  f: FleetVulnFilters,
): Promise<{ rows: FleetVulnRow[]; total: number }> {
  const orderBy =
    f.sort === "hosts"
      ? "g.affected_hosts DESC, g.top_key DESC, g.vuln_key"
      : f.sort === "recent"
        ? "g.first_seen_at DESC, g.top_key DESC, g.vuln_key"
        : "g.top_key DESC, g.affected_hosts DESC, g.vuln_key";
  // One row per vuln_key over this user's findings. "open" lists vulns
  // affecting at least one host now; "resolved" lists vulns that affected
  // hosts before and none now. Severity/fix columns come from the open
  // rows when there are any, otherwise from the resolved ones.
  const { rows } = await pool.query<{
    vuln_key: string;
    severity: string | null;
    is_kev: boolean;
    epss_score: string | null;
    cvss_v3_score: string | null;
    affected_hosts: string;
    previous_hosts: string;
    packages: string[];
    any_fix: boolean;
    pro_only: boolean;
    no_fix: boolean;
    first_seen_at: Date;
    description: string | null;
    total: string;
  }>(
    `WITH uf AS (
       SELECT f.*
       FROM hosts h
       JOIN findings f ON f.host_id = h.id
       WHERE h.user_id = $1 AND f.kind = 'vulnerable_package'
     ),
     g AS (
       SELECT uf.vuln_key,
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
              bool_or($3::text IS NULL
                      OR strpos(lower(uf.vuln_key), lower($3)) > 0
                      OR strpos(lower(coalesce(uf.source_package, '')), lower($3)) > 0) AS q_match
       FROM uf
       GROUP BY uf.vuln_key
     )
     SELECT g.vuln_key, g.severity, g.is_kev, g.epss_score, g.cvss_v3_score,
            g.affected_hosts, g.previous_hosts, g.packages, g.any_fix,
            g.pro_only, g.no_fix, g.first_seen_at,
            left(c.description, 200) AS description,
            count(*) OVER () AS total
     FROM g
     LEFT JOIN cves c ON c.id = g.vuln_key
     WHERE (CASE WHEN $2 = 'open' THEN g.affected_hosts > 0
                 ELSE g.affected_hosts = 0 AND g.previous_hosts > 0 END)
       AND g.q_match
       AND ($4::text IS NULL OR g.severity = $4)
       AND (NOT $5::boolean OR g.is_kev)
       AND ($6::text IS NULL
            OR ($6 = 'available' AND g.any_fix)
            OR ($6 = 'pro' AND g.pro_only)
            OR ($6 = 'none' AND g.no_fix))
     ORDER BY ${orderBy}
     LIMIT $7 OFFSET $8`,
    [userId, f.status, f.q, f.severity, f.kev, f.fix, f.pageSize, (f.page - 1) * f.pageSize],
  );
  return {
    rows: rows.map((r) => ({
      vulnKey: r.vuln_key,
      severity: r.severity,
      isKev: r.is_kev,
      epssScore: num(r.epss_score),
      cvssV3Score: num(r.cvss_v3_score),
      affectedHosts: Number(r.affected_hosts),
      previousHosts: Number(r.previous_hosts),
      packages: (r.packages ?? []).filter((p): p is string => p !== null),
      anyFix: r.any_fix,
      proOnly: r.pro_only,
      noFix: r.no_fix,
      firstSeenAt: r.first_seen_at.toISOString(),
      description: r.description,
    })),
    total: rows[0] ? Number(rows[0].total) : 0,
  };
}

export type VulnHostRow = FindingRow & { hostId: string; hostname: string; label: string | null };

export type AffectedVersionRow = {
  distro: string;
  release: string;
  name: string;
  version: string;
  arch: string;
  sourcePackage: string | null;
  fixedVersion: string | null;
  fixChannel: string | null;
  isKernel: boolean;
  hosts: number;
};

export type ReleaseFixRow = {
  distro: string;
  release: string;
  sourcePackage: string;
  channel: string;
  status: string;
  fixedVersion: string | null;
  distroSeverity: string | null;
  advisoryIds: string[];
};

export type FleetVulnDetail = {
  cve: CveDetail | null;
  advisories: AdvisoryDetail[];
  releaseFixes: ReleaseFixRow[];
  releaseFixesTruncated: boolean;
  versions: AffectedVersionRow[];
  affected: VulnHostRow[];
  previous: VulnHostRow[];
};

const RELEASE_FIX_LIMIT = 200;

// Null when nothing at all is known about vulnKey (no cves row, no
// advisory, no finding of this user's): the page 404s.
export async function getFleetVulnDetail(
  userId: string,
  vulnKey: string,
): Promise<FleetVulnDetail | null> {
  const [cve, adv, fnd, versions] = await Promise.all([
    getCve(vulnKey),
    pool.query<AdvisoryDbRow>(
      `SELECT ${ADVISORY_COLUMNS} FROM advisories a
       WHERE a.vuln_key = $1 OR a.cve_ids @> ARRAY[$1]::text[] -- advisories_cve_ids_idx (GIN)
       ORDER BY a.source, a.id`,
      [vulnKey],
    ),
    pool.query<
      FindingDbRow & { status: string; host_id: string; hostname: string; label: string | null }
    >(
      `SELECT ${FINDING_COLUMNS}, NULL::text AS description, f.status,
              h.id AS host_id, h.hostname, h.label
       FROM hosts h
       JOIN findings f ON f.host_id = h.id
       WHERE h.user_id = $1 AND f.kind = 'vulnerable_package' AND f.vuln_key = $2
       ORDER BY f.severity_key DESC, h.hostname, h.id, f.source_package`,
      [userId, vulnKey],
    ),
    // Versions matched for this vuln that are installed on the user's
    // hosts now. Reached through host_software, never software_versions
    // directly; includes kernels that aren't running (no finding).
    pool.query<{
      distro: string;
      release: string;
      name: string;
      version: string;
      arch: string;
      match_source: string | null;
      fixed_version: string | null;
      fix_channel: string | null;
      is_kernel: boolean;
      hosts: string;
    }>(
      `SELECT sv.distro, sv.release, sv.name, sv.version, sv.arch, sv.match_source,
              sw.fixed_version, sw.fix_channel, sv.kernel_release IS NOT NULL AS is_kernel,
              count(DISTINCT h.id) AS hosts
       FROM hosts h
       JOIN host_software hs ON hs.host_id = h.id AND hs.removed_at IS NULL
       JOIN software_vulnerabilities sw ON sw.software_id = hs.software_id AND sw.vuln_key = $2
       JOIN software_versions sv ON sv.id = hs.software_id
       WHERE h.user_id = $1
       GROUP BY sv.id, sw.fixed_version, sw.fix_channel
       ORDER BY hosts DESC, sv.release, sv.name, sv.arch`,
      [userId, vulnKey],
    ),
  ]);
  if (!cve && adv.rows.length === 0 && fnd.rows.length === 0) return null;

  const advIds = adv.rows.map((a) => a.id);
  const fixes = advIds.length
    ? await pool.query<{
        distro: string;
        release: string;
        source_package: string;
        channel: string;
        status: string;
        fixed_version: string | null;
        distro_severity: string | null;
        advisory_ids: string[];
      }>(
        `SELECT aa.distro, aa.release, aa.source_package, aa.channel, aa.status,
                aa.fixed_version, max(aa.distro_severity) AS distro_severity,
                array_agg(DISTINCT aa.advisory_id ORDER BY aa.advisory_id) AS advisory_ids
         FROM advisory_affected aa
         JOIN distro_releases dr ON dr.distro = aa.distro AND dr.codename = aa.release
         WHERE aa.advisory_id = ANY ($1::text[])
         GROUP BY aa.distro, aa.release, dr.version, aa.source_package, aa.channel,
                  aa.status, aa.fixed_version
         ORDER BY aa.distro, dr.version DESC, aa.source_package, aa.channel
         LIMIT $2`,
        [advIds, RELEASE_FIX_LIMIT + 1],
      )
    : { rows: [] };

  const hostRow = (r: (typeof fnd.rows)[number]): VulnHostRow => ({
    ...mapFinding(r),
    hostId: r.host_id,
    hostname: r.hostname,
    label: r.label,
  });
  return {
    cve,
    advisories: adv.rows.map(mapAdvisory),
    releaseFixes: fixes.rows.slice(0, RELEASE_FIX_LIMIT).map((r) => ({
      distro: r.distro,
      release: r.release,
      sourcePackage: r.source_package,
      channel: r.channel,
      status: r.status,
      fixedVersion: r.fixed_version,
      distroSeverity: r.distro_severity,
      advisoryIds: r.advisory_ids,
    })),
    releaseFixesTruncated: fixes.rows.length > RELEASE_FIX_LIMIT,
    versions: versions.rows.map((r) => ({
      distro: r.distro,
      release: r.release,
      name: r.name,
      version: r.version,
      arch: r.arch,
      sourcePackage: r.match_source,
      fixedVersion: r.fixed_version,
      fixChannel: r.fix_channel,
      isKernel: r.is_kernel,
      hosts: Number(r.hosts),
    })),
    affected: fnd.rows.filter((r) => r.status === "open").map(hostRow),
    previous: fnd.rows.filter((r) => r.status === "resolved").map(hostRow),
  };
}
