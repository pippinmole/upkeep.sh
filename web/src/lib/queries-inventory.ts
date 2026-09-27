import { cache } from "react";

import { pool } from "./db";

// Package inventory reads (DOMAIN_MODEL.md §3). Source of truth is
// host_software validity ranges over interned software_versions rows.
//
// Tenancy: software_versions is shared fleet-wide ACROSS USERS (a version
// row is interned once for everyone). Every query here therefore starts
// from `hosts h ... WHERE h.user_id = $1` and only ever reaches
// software_versions through that user's host_software rows. Never select
// from software_versions without that join.
//
// Archived hosts (hosts.archived_at, DOMAIN_MODEL.md §4.3) are left out of
// every fleet-wide query (`AND h.archived_at IS NULL`); per-host pages
// still show their full history.

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(s: string): boolean {
  return UUID_RE.test(s);
}

// Exact UTC rendering of a timestamptz, microseconds included. JS Date
// only has milliseconds, so range boundaries that round-trip through the
// URL (?at=, ?before=) or are compared for equality use this text form and
// are passed back to Postgres as ::timestamptz, never as Date.
const utcKey = (col: string) =>
  `to_char(${col} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;

// ---------------------------------------------------------------------------
// Host detail
// ---------------------------------------------------------------------------

export type CollectorStatus = {
  status: string;
  error?: string;
  reason?: string;
};

export type HostDetail = {
  id: string;
  hostname: string;
  label: string | null;
  createdAt: string;
  lastSeenAt: string | null;
  latestSnapshot: {
    id: string;
    collectedAt: string;
    osId: string;
    osVersionId: string;
    osCodename: string | null;
    rebootRequired: boolean;
    rebootPackages: string[];
    // PROTOCOL.md `collectors`; null for agents that predate it.
    collectorStatus: Record<string, CollectorStatus> | null;
  } | null;
  // Running kernel (`uname -r`) from the newest snapshot by collected_at,
  // the same rule the matcher's running-kernel policy uses. Null = unknown
  // (agent predates the kernel collector, or it failed).
  runningKernel: string | null;
  inventory: {
    ecosystem: string;
    openPackages: number;
    confirmedAt: string;
    changedAt: string;
  }[];
};

// cache(): the host layout and each tab page both call this in the same
// request; React dedupes it. Returns null when the host doesn't exist OR
// isn't owned by userId: callers must notFound() either way.
export const getHost = cache(async function getHost(
  userId: string,
  hostId: string,
): Promise<HostDetail | null> {
  if (!isUuid(hostId)) return null;

  const { rows } = await pool.query<{
    id: string;
    hostname: string;
    label: string | null;
    created_at: Date;
    last_seen_at: Date | null;
    snapshot_id: string | null;
    collected_at: Date | null;
    os_id: string | null;
    os_version_id: string | null;
    os_codename: string | null;
    reboot_required: boolean | null;
    reboot_packages: string[] | null;
    collector_status: Record<string, CollectorStatus> | null;
    running_kernel: string | null;
  }>(
    `SELECT h.id, h.hostname, h.label, h.created_at, h.last_seen_at,
            s.id AS snapshot_id, s.collected_at, s.os_id, s.os_version_id,
            s.os_codename, s.reboot_required, s.reboot_packages,
            s.collector_status, rk.kernel_release AS running_kernel
     FROM hosts h
     LEFT JOIN LATERAL (
       SELECT * FROM snapshots s
       WHERE s.host_id = h.id
       ORDER BY s.received_at DESC   -- snapshots_host_id_received_at_idx
       LIMIT 1
     ) s ON true
     LEFT JOIN LATERAL (
       -- As host_kernel_packages: newest by collected_at.
       SELECT s2.kernel_release FROM snapshots s2
       WHERE s2.host_id = h.id
       ORDER BY s2.collected_at DESC   -- snapshots_host_collected_idx
       LIMIT 1
     ) rk ON true
     WHERE h.id = $2 AND h.user_id = $1`,
    [userId, hostId],
  );
  const r = rows[0];
  if (!r) return null;

  const inv = await pool.query<{
    ecosystem: string;
    open_packages: string;
    confirmed_at: Date;
    changed_at: Date;
  }>(
    `SELECT st.ecosystem, st.confirmed_at, st.changed_at,
            (SELECT count(*)
             FROM host_software hs
             JOIN software_versions sv ON sv.id = hs.software_id
             WHERE hs.host_id = h.id AND hs.removed_at IS NULL
               AND sv.ecosystem = st.ecosystem) AS open_packages
     FROM hosts h
     JOIN host_inventory_state st ON st.host_id = h.id
     WHERE h.id = $2 AND h.user_id = $1
     ORDER BY st.ecosystem`,
    [userId, hostId],
  );

  return {
    id: r.id,
    hostname: r.hostname,
    label: r.label,
    createdAt: r.created_at.toISOString(),
    lastSeenAt: r.last_seen_at?.toISOString() ?? null,
    latestSnapshot:
      r.snapshot_id && r.collected_at
        ? {
            id: r.snapshot_id,
            collectedAt: r.collected_at.toISOString(),
            osId: r.os_id ?? "",
            osVersionId: r.os_version_id ?? "",
            osCodename: r.os_codename,
            rebootRequired: r.reboot_required ?? false,
            rebootPackages: r.reboot_packages ?? [],
            collectorStatus: r.collector_status,
          }
        : null,
    runningKernel: r.running_kernel,
    inventory: inv.rows.map((i) => ({
      ecosystem: i.ecosystem,
      openPackages: Number(i.open_packages),
      confirmedAt: i.confirmed_at.toISOString(),
      changedAt: i.changed_at.toISOString(),
    })),
  };
});

// ---------------------------------------------------------------------------
// Per-host packages (current or point-in-time)
// ---------------------------------------------------------------------------

export type HostPackageRow = {
  // software_versions.id: the key for the row sheet (?pkg=) and the
  // software_vulnerabilities / host_package_vuln_status joins.
  softwareId: string;
  ecosystem: string;
  name: string;
  version: string;
  arch: string;
  sourceName: string | null;
  sourceVersion: string | null;
  sourceInferred: boolean;
  firstSeenAt: string;
  removedAt: string | null;
  // Highest standard-archive fix over this version's matches
  // (software_versions.max_fixed_version, written by the matcher).
  maxFixedVersion: string | null;
  // `uname -r` for kernel image/module binaries, else null.
  kernelRelease: string | null;
  // This host's open findings the binary contributes to
  // (host_package_vuln_status). Current view only; zero under ?at=.
  vuln: {
    open: number;
    topSeverity: string | null;
    kev: number;
    fixable: number;
    proOnly: number;
    unfixed: number;
  };
  // Matches for this version under today's advisory data
  // (software_vulnerabilities), whether or not a finding was raised: the
  // ?at= view's status, and non-running kernels' informational count.
  known: { total: number; unfixed: number; kev: number };
};

export type PackageStatusFilter = "vulnerable" | "kev" | "no-fix";

export type HostPackageFilters = {
  q: string | null; // substring of binary or source name, case-insensitive
  ecosystem: string | null;
  // Point in time as an exact timestamptz string (see parseAt); null =
  // current (open ranges).
  at: string | null;
  status: PackageStatusFilter | null;
  sort: "severity" | "name";
  page: number; // 1-based
  pageSize: number;
};

export async function getHostPackages(
  userId: string,
  hostId: string,
  f: HostPackageFilters,
): Promise<{ rows: HostPackageRow[]; total: number }> {
  if (!isUuid(hostId)) return { rows: [], total: 0 };

  // Only the range predicate differs between "current" and "?at=". Both are
  // static SQL; the timestamp is a bound parameter. The current form keeps
  // the literal `removed_at IS NULL` so the host_software_open_uq partial
  // index is usable.
  const rangePredicate =
    f.at === null
      ? // $3 is NULL here; referenced only so its type is known.
        "hs.removed_at IS NULL AND $3::timestamptz IS NULL"
      : "hs.first_seen_at <= $3::timestamptz AND (hs.removed_at IS NULL OR hs.removed_at > $3::timestamptz)";
  const orderBy =
    f.sort === "name"
      ? "r.name, r.arch, r.version"
      : "r.top_severity_key DESC NULLS LAST, r.vuln_n DESC, r.name, r.arch, r.version";

  // Status filter / severity sort use open findings in the current view
  // and today's matches (software_vulnerabilities) under ?at=, where
  // findings (current state) don't apply. vs is reached only through inv,
  // i.e. this user's host_software rows.
  const { rows } = await pool.query<{
    software_id: string;
    ecosystem: string;
    name: string;
    version: string;
    arch: string;
    source_name: string | null;
    source_version: string | null;
    source_inferred: boolean;
    first_seen_at: Date;
    removed_at: Date | null;
    max_fixed_version: string | null;
    kernel_release: string | null;
    open_findings: string;
    top_severity: string | null;
    kev_count: string;
    fixable_count: string;
    pro_only_count: string;
    unfixed_count: string;
    known: string;
    known_unfixed: string;
    known_kev: string;
    total: string;
  }>(
    `WITH inv AS (
       SELECT hs.software_id, hs.first_seen_at, hs.removed_at
       FROM hosts h
       JOIN host_software hs ON hs.host_id = h.id
       WHERE h.id = $2 AND h.user_id = $1
         AND ${rangePredicate}
     ),
     r AS (
       SELECT sv.id AS software_id, sv.ecosystem, sv.name, sv.version, sv.arch,
              sv.source_name, sv.source_version, sv.source_inferred,
              sv.max_fixed_version, sv.kernel_release,
              inv.first_seen_at, inv.removed_at,
              coalesce(vs.open_findings, 0) AS open_findings,
              vs.top_severity, vs.top_severity_key,
              coalesce(vs.kev_count, 0) AS kev_count,
              coalesce(vs.fixable_count, 0) AS fixable_count,
              coalesce(vs.pro_only_count, 0) AS pro_only_count,
              coalesce(vs.unfixed_count, 0) AS unfixed_count,
              k.known, k.known_unfixed, k.known_kev,
              CASE WHEN $3::timestamptz IS NULL THEN coalesce(vs.open_findings, 0)
                   ELSE k.known END AS vuln_n,
              CASE WHEN $3::timestamptz IS NULL THEN coalesce(vs.kev_count, 0)
                   ELSE k.known_kev END AS kev_n,
              CASE WHEN $3::timestamptz IS NULL THEN coalesce(vs.unfixed_count, 0)
                   ELSE k.known_unfixed END AS nofix_n
       FROM inv
       JOIN software_versions sv ON sv.id = inv.software_id
       LEFT JOIN host_package_vuln_status vs
         ON vs.host_id = $2 AND vs.software_id = inv.software_id
        AND $3::timestamptz IS NULL
       CROSS JOIN LATERAL (
         SELECT count(*) AS known,
                count(*) FILTER (WHERE sw.fixed_version IS NULL) AS known_unfixed,
                count(*) FILTER (WHERE c.is_kev) AS known_kev
         FROM software_vulnerabilities sw
         LEFT JOIN cves c ON c.id = sw.vuln_key
         WHERE sw.software_id = inv.software_id
       ) k
       WHERE ($4::text IS NULL OR sv.ecosystem = $4)
         AND ($5::text IS NULL
              OR strpos(lower(sv.name), lower($5)) > 0
              OR strpos(lower(coalesce(sv.source_name, '')), lower($5)) > 0)
     )
     SELECT r.*, count(*) OVER () AS total
     FROM r
     WHERE ($8::text IS NULL
            OR ($8 = 'vulnerable' AND r.vuln_n > 0)
            OR ($8 = 'kev' AND r.kev_n > 0)
            OR ($8 = 'no-fix' AND r.nofix_n > 0))
     ORDER BY ${orderBy}
     LIMIT $6 OFFSET $7`,
    [userId, hostId, f.at, f.ecosystem, f.q, f.pageSize, (f.page - 1) * f.pageSize, f.status],
  );
  return {
    rows: rows.map((r) => ({
      softwareId: r.software_id,
      ecosystem: r.ecosystem,
      name: r.name,
      version: r.version,
      arch: r.arch,
      sourceName: r.source_name,
      sourceVersion: r.source_version,
      sourceInferred: r.source_inferred,
      firstSeenAt: r.first_seen_at.toISOString(),
      removedAt: r.removed_at?.toISOString() ?? null,
      maxFixedVersion: r.max_fixed_version,
      kernelRelease: r.kernel_release,
      vuln: {
        open: Number(r.open_findings),
        topSeverity: r.top_severity,
        kev: Number(r.kev_count),
        fixable: Number(r.fixable_count),
        proOnly: Number(r.pro_only_count),
        unfixed: Number(r.unfixed_count),
      },
      known: {
        total: Number(r.known),
        unfixed: Number(r.known_unfixed),
        kev: Number(r.known_kev),
      },
    })),
    total: rows[0] ? Number(rows[0].total) : 0,
  };
}

// Ecosystems this host has ever had inventory for (filter options).
export async function getHostEcosystems(userId: string, hostId: string): Promise<string[]> {
  if (!isUuid(hostId)) return [];
  const { rows } = await pool.query<{ ecosystem: string }>(
    `SELECT st.ecosystem
     FROM hosts h
     JOIN host_inventory_state st ON st.host_id = h.id
     WHERE h.id = $2 AND h.user_id = $1
     ORDER BY st.ecosystem`,
    [userId, hostId],
  );
  return rows.map((r) => r.ecosystem);
}

// ---------------------------------------------------------------------------
// Per-host change history
// ---------------------------------------------------------------------------

export type RangeEvent = {
  kind: "open" | "close";
  softwareId: string;
  at: string; // exact UTC range boundary (collected_at, clamped); see utcKey
  snapshotId: string | null;
  ecosystem: string;
  name: string;
  version: string;
  arch: string;
  sourceName: string | null;
};

export type HistoryPage = {
  // Newest first. Each boundary is one applied inventory diff.
  boundaries: {
    at: string;
    events: RangeEvent[];
    // True when this boundary is the first inventory recorded for an
    // ecosystem on this host (every event is an open of the baseline).
    baselineEcosystems: string[];
  }[];
  // Cursor for the next (older) page, or null if this is the last page.
  nextBefore: string | null;
};

export async function getHostHistory(
  userId: string,
  hostId: string,
  opts: { before: string | null; limit: number },
): Promise<HistoryPage> {
  if (!isUuid(hostId)) return { boundaries: [], nextBefore: null };

  // 1. The newest `limit` boundaries (distinct range open/close times)
  //    older than the cursor. Each side is a host_software_opened_idx /
  //    host_software_removed_idx range scan.
  const b = await pool.query<{ at: string }>(
    `WITH owned AS (SELECT id FROM hosts WHERE id = $2 AND user_id = $1)
     SELECT ${utcKey("at")} AS at FROM (
       SELECT hs.first_seen_at AS at
       FROM host_software hs JOIN owned ON hs.host_id = owned.id
       WHERE ($3::timestamptz IS NULL OR hs.first_seen_at < $3::timestamptz)
       UNION
       SELECT hs.removed_at
       FROM host_software hs JOIN owned ON hs.host_id = owned.id
       WHERE hs.removed_at IS NOT NULL
         AND ($3::timestamptz IS NULL OR hs.removed_at < $3::timestamptz)
     ) b
     ORDER BY at DESC
     LIMIT $4`,
    [userId, hostId, opts.before, opts.limit + 1],
  );
  const all = b.rows.map((r) => r.at);
  // at strings are fixed-width UTC, so string order == time order.
  const page = all.slice(0, opts.limit);
  if (page.length === 0) return { boundaries: [], nextBefore: null };
  const newest = page[0];
  const oldest = page[page.length - 1];

  // 2. Every open/close within [oldest, newest], plus each ecosystem's
  //    first-ever open time (to recognise the baseline inventory).
  const ev = await pool.query<{
    kind: "open" | "close";
    software_id: string;
    at: string;
    snapshot_id: string | null;
    ecosystem: string;
    name: string;
    version: string;
    arch: string;
    source_name: string | null;
  }>(
    `WITH owned AS (SELECT id FROM hosts WHERE id = $2 AND user_id = $1)
     SELECT 'open' AS kind, hs.software_id, ${utcKey("hs.first_seen_at")} AS at,
            hs.first_seen_snapshot_id AS snapshot_id,
            sv.ecosystem, sv.name, sv.version, sv.arch, sv.source_name
     FROM host_software hs
     JOIN owned ON hs.host_id = owned.id
     JOIN software_versions sv ON sv.id = hs.software_id
     WHERE hs.first_seen_at BETWEEN $3::timestamptz AND $4::timestamptz
     UNION ALL
     SELECT 'close', hs.software_id, ${utcKey("hs.removed_at")}, hs.removed_snapshot_id,
            sv.ecosystem, sv.name, sv.version, sv.arch, sv.source_name
     FROM host_software hs
     JOIN owned ON hs.host_id = owned.id
     JOIN software_versions sv ON sv.id = hs.software_id
     WHERE hs.removed_at BETWEEN $3::timestamptz AND $4::timestamptz
     ORDER BY at DESC, name, arch, kind DESC`,
    [userId, hostId, oldest, newest],
  );
  const firsts = await pool.query<{ ecosystem: string; first_at: string }>(
    `SELECT sv.ecosystem, ${utcKey("min(hs.first_seen_at)")} AS first_at
     FROM hosts h
     JOIN host_software hs ON hs.host_id = h.id
     JOIN software_versions sv ON sv.id = hs.software_id
     WHERE h.id = $2 AND h.user_id = $1
     GROUP BY sv.ecosystem`,
    [userId, hostId],
  );

  const byAt = new Map<string, RangeEvent[]>();
  for (const at of page) byAt.set(at, []);
  for (const e of ev.rows) {
    byAt.get(e.at)?.push({
      kind: e.kind,
      softwareId: e.software_id,
      at: e.at,
      snapshotId: e.snapshot_id,
      ecosystem: e.ecosystem,
      name: e.name,
      version: e.version,
      arch: e.arch,
      sourceName: e.source_name,
    });
  }

  return {
    boundaries: page.map((at) => ({
      at,
      events: byAt.get(at) ?? [],
      baselineEcosystems: firsts.rows.filter((f) => f.first_at === at).map((f) => f.ecosystem),
    })),
    nextBefore: all.length > opts.limit ? oldest : null,
  };
}

// ---------------------------------------------------------------------------
// Fleet packages
// ---------------------------------------------------------------------------

export type FleetPackageRow = {
  ecosystem: string;
  name: string;
  versions: number;
  hosts: number;
  sampleVersions: string[]; // up to a few distinct versions, for display
};

export async function getFleetPackages(
  userId: string,
  f: {
    q: string | null;
    ecosystem: string | null;
    sort: "name" | "hosts";
    page: number;
    pageSize: number;
  },
): Promise<{ rows: FleetPackageRow[]; total: number }> {
  const orderBy = f.sort === "hosts" ? "hosts DESC, name, ecosystem" : "name, ecosystem";
  const { rows } = await pool.query<{
    ecosystem: string;
    name: string;
    versions: string;
    hosts: string;
    sample_versions: string[];
    total: string;
  }>(
    `SELECT sv.ecosystem, sv.name,
            count(DISTINCT sv.version) AS versions,
            count(DISTINCT h.id) AS hosts,
            (array_agg(DISTINCT sv.version))[1:4] AS sample_versions,
            count(*) OVER () AS total
     FROM hosts h
     JOIN host_software hs ON hs.host_id = h.id AND hs.removed_at IS NULL
     JOIN software_versions sv ON sv.id = hs.software_id
     WHERE h.user_id = $1 AND h.archived_at IS NULL
       AND ($2::text IS NULL OR sv.ecosystem = $2)
       AND ($3::text IS NULL
            OR strpos(lower(sv.name), lower($3)) > 0
            OR strpos(lower(coalesce(sv.source_name, '')), lower($3)) > 0)
     GROUP BY sv.ecosystem, sv.name
     ORDER BY ${orderBy}
     LIMIT $4 OFFSET $5`,
    [userId, f.ecosystem, f.q, f.pageSize, (f.page - 1) * f.pageSize],
  );
  return {
    rows: rows.map((r) => ({
      ecosystem: r.ecosystem,
      name: r.name,
      versions: Number(r.versions),
      hosts: Number(r.hosts),
      sampleVersions: r.sample_versions,
    })),
    total: rows[0] ? Number(rows[0].total) : 0,
  };
}

export async function getFleetEcosystems(userId: string): Promise<string[]> {
  const { rows } = await pool.query<{ ecosystem: string }>(
    `SELECT DISTINCT st.ecosystem
     FROM hosts h
     JOIN host_inventory_state st ON st.host_id = h.id
     WHERE h.user_id = $1 AND h.archived_at IS NULL
     ORDER BY st.ecosystem`,
    [userId],
  );
  return rows.map((r) => r.ecosystem);
}

export type PackageVersionRow = {
  ecosystem: string;
  distro: string;
  release: string;
  version: string;
  arch: string;
  sourceName: string | null;
  sourceVersion: string | null;
  hosts: number;
};

export type PackageHostRow = {
  hostId: string;
  hostname: string;
  label: string | null;
  ecosystem: string;
  distro: string;
  release: string;
  version: string;
  arch: string;
  since: string;
};

export type PackageFormerHostRow = {
  hostId: string;
  hostname: string;
  label: string | null;
  ecosystem: string;
  lastVersion: string;
  arch: string;
  removedAt: string;
};

export async function getFleetPackage(
  userId: string,
  name: string,
): Promise<{
  versions: PackageVersionRow[];
  hosts: PackageHostRow[];
  formerHosts: PackageFormerHostRow[];
}> {
  // Current installs of this name on the user's hosts. Planner can go
  // software_versions_name_idx (=) -> host_software_open_by_software_idx ->
  // hosts pk, filtered by user_id.
  const current = await pool.query<{
    host_id: string;
    hostname: string;
    label: string | null;
    ecosystem: string;
    distro: string;
    release: string;
    version: string;
    arch: string;
    source_name: string | null;
    source_version: string | null;
    first_seen_at: Date;
  }>(
    `SELECT h.id AS host_id, h.hostname, h.label,
            sv.ecosystem, sv.distro, sv.release, sv.version, sv.arch,
            sv.source_name, sv.source_version, hs.first_seen_at
     FROM hosts h
     JOIN host_software hs ON hs.host_id = h.id AND hs.removed_at IS NULL
     JOIN software_versions sv ON sv.id = hs.software_id
     WHERE h.user_id = $1 AND h.archived_at IS NULL AND sv.name = $2
     ORDER BY h.hostname, h.id, sv.arch`,
    [userId, name],
  );

  // Hosts that had this name at some point but have no open range for it
  // now: their most recent closed range.
  const former = await pool.query<{
    host_id: string;
    hostname: string;
    label: string | null;
    ecosystem: string;
    version: string;
    arch: string;
    removed_at: Date;
  }>(
    `SELECT * FROM (
       SELECT DISTINCT ON (h.id)
              h.id AS host_id, h.hostname, h.label,
              sv.ecosystem, sv.version, sv.arch, hs.removed_at
       FROM hosts h
       JOIN host_software hs ON hs.host_id = h.id AND hs.removed_at IS NOT NULL
       JOIN software_versions sv ON sv.id = hs.software_id
       WHERE h.user_id = $1 AND h.archived_at IS NULL AND sv.name = $2
         AND NOT EXISTS (
           SELECT 1
           FROM host_software hs2
           JOIN software_versions sv2 ON sv2.id = hs2.software_id
           WHERE hs2.host_id = h.id AND hs2.removed_at IS NULL
             AND sv2.name = $2
         )
       ORDER BY h.id, hs.removed_at DESC
     ) f
     ORDER BY removed_at DESC`,
    [userId, name],
  );

  // Versions table derived from the rows above: never read
  // software_versions directly (it is shared across users).
  const versions = new Map<string, PackageVersionRow>();
  for (const r of current.rows) {
    const key = [r.ecosystem, r.distro, r.release, r.version, r.arch].join("\0");
    const v = versions.get(key);
    if (v) v.hosts++;
    else
      versions.set(key, {
        ecosystem: r.ecosystem,
        distro: r.distro,
        release: r.release,
        version: r.version,
        arch: r.arch,
        sourceName: r.source_name,
        sourceVersion: r.source_version,
        hosts: 1,
      });
  }

  return {
    versions: [...versions.values()].sort(
      (a, b) =>
        b.hosts - a.hosts ||
        a.distro.localeCompare(b.distro) ||
        a.release.localeCompare(b.release) ||
        a.arch.localeCompare(b.arch),
    ),
    hosts: current.rows.map((r) => ({
      hostId: r.host_id,
      hostname: r.hostname,
      label: r.label,
      ecosystem: r.ecosystem,
      distro: r.distro,
      release: r.release,
      version: r.version,
      arch: r.arch,
      since: r.first_seen_at.toISOString(),
    })),
    formerHosts: former.rows.map((r) => ({
      hostId: r.host_id,
      hostname: r.hostname,
      label: r.label,
      ecosystem: r.ecosystem,
      lastVersion: r.version,
      arch: r.arch,
      removedAt: r.removed_at.toISOString(),
    })),
  };
}
