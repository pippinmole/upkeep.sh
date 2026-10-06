import { pool } from "./db";
import { isUuid } from "./queries-inventory";
import { FINDING_KIND, type VulnKind } from "./vuln-tables";

// Finding lifecycle reads for the MCP tools (docs/MCP.md#tools):
// get_finding_status (is this package or vulnerability still open on a
// host, and how fresh is the host's data) and list_resolved (findings
// resolved since a time). Straight off `findings`, which the Go worker
// reconciles after each snapshot.
//
// Tenancy as in queries-vulns.ts: every read starts from the workspace's
// hosts (`h.workspace_id = $1`); the fleet-wide read skips archived hosts.

const iso = (d: Date | null): string | null => d?.toISOString() ?? null;

export type FindingStatusRow = {
  vulnKey: string;
  sourcePackage: string | null;
  packages: string[];
  status: "open" | "resolved";
  installedVersion: string | null;
  fixedVersion: string | null;
  fixChannel: string | null;
  severity: string | null;
  isKev: boolean;
  firstSeenAt: string;
  resolvedAt: string | null;
  reopenedAt: string | null;
};

export type InstalledPackage = {
  name: string;
  version: string;
  arch: string;
  sourceName: string | null;
  sourceVersion: string | null;
  since: string;
};

export type HostFreshness = {
  // Newest snapshot by collected_at (the matcher's rule), and when the
  // server received it.
  snapshotCollectedAt: string | null;
  snapshotReceivedAt: string | null;
  // The shortest push interval among the host's enabled, non-revoked
  // agents (seconds, 900 when an agent doesn't say); null with no agent.
  pushIntervalSeconds: number | null;
};

export type FindingStatus = {
  findings: FindingStatusRow[];
  total: number;
  open: number;
  // Open findings with no fix published: an upgrade can't close them.
  openUnfixed: number;
  // The package's binaries installed now (package lookups only).
  installed: InstalledPackage[];
  freshness: HostFreshness;
};

export type FindingStatusQuery = {
  // Source or binary package name, case-insensitive.
  package: string | null;
  // CVE or advisory id, case-insensitive.
  vulnKey: string | null;
  limit: number;
};

// Host package findings (vulnerable_package) of one host matching the
// package and/or vulnerability, open first, then most urgent.
export async function getFindingStatus(
  workspaceId: string,
  hostId: string,
  q: FindingStatusQuery,
): Promise<FindingStatus> {
  const empty: FindingStatus = {
    findings: [],
    total: 0,
    open: 0,
    openUnfixed: 0,
    installed: [],
    freshness: { snapshotCollectedAt: null, snapshotReceivedAt: null, pushIntervalSeconds: null },
  };
  if (!isUuid(hostId)) return empty;
  const [findings, installed, freshness] = await Promise.all([
    pool.query<{
      vuln_key: string;
      source_package: string | null;
      packages: string[];
      status: "open" | "resolved";
      installed_version: string | null;
      fixed_version: string | null;
      fix_channel: string | null;
      severity: string | null;
      is_kev: boolean;
      first_seen_at: Date;
      resolved_at: Date | null;
      reopened_at: Date | null;
      total: string;
      open_total: string;
      open_unfixed: string;
    }>(
      `SELECT f.vuln_key, f.source_package, f.packages, f.status, f.installed_version,
              f.fixed_version, f.fix_channel, f.severity, f.is_kev, f.first_seen_at,
              f.resolved_at, f.reopened_at,
              count(*) OVER () AS total,
              count(*) FILTER (WHERE f.status = 'open') OVER () AS open_total,
              count(*) FILTER (WHERE f.status = 'open' AND f.fixed_version IS NULL) OVER ()
                AS open_unfixed
       FROM hosts h
       JOIN findings f ON f.host_id = h.id AND f.kind = 'vulnerable_package'
       WHERE h.id = $2 AND h.workspace_id = $1
         AND ($3::text IS NULL
              OR lower(f.source_package) = lower($3)
              OR EXISTS (SELECT 1 FROM unnest(f.packages) p WHERE lower(p) = lower($3)))
         AND ($4::text IS NULL OR lower(f.vuln_key) = lower($4))
       ORDER BY f.status = 'open' DESC, f.severity_key DESC, f.vuln_key, f.source_package
       LIMIT $5`,
      [workspaceId, hostId, q.package, q.vulnKey, q.limit],
    ),
    q.package === null
      ? Promise.resolve({ rows: [] })
      : pool.query<{
          name: string;
          version: string;
          arch: string;
          source_name: string | null;
          source_version: string | null;
          first_seen_at: Date;
        }>(
          `SELECT sv.name, sv.version, sv.arch, sv.source_name, sv.source_version,
                  hs.first_seen_at
           FROM hosts h
           JOIN host_software hs ON hs.host_id = h.id AND hs.removed_at IS NULL
           JOIN software_versions sv ON sv.id = hs.software_id
           WHERE h.id = $2 AND h.workspace_id = $1
             AND (lower(sv.name) = lower($3) OR lower(sv.source_name) = lower($3))
           ORDER BY sv.name, sv.arch, sv.version`,
          [workspaceId, hostId, q.package],
        ),
    pool.query<{
      collected_at: Date | null;
      received_at: Date | null;
      push_interval_seconds: number | null;
    }>(
      `SELECT s.collected_at, s.received_at,
              (SELECT min(coalesce(a.push_interval_seconds, 900))
               FROM agent_hosts ah
               JOIN agents a ON a.id = ah.agent_id AND a.workspace_id = h.workspace_id
               WHERE ah.host_id = h.id AND ah.enabled AND a.revoked_at IS NULL)
                AS push_interval_seconds
       FROM hosts h
       LEFT JOIN LATERAL (
         SELECT sn.collected_at, sn.received_at FROM snapshots sn
         WHERE sn.host_id = h.id
         ORDER BY sn.collected_at DESC LIMIT 1   -- snapshots_host_collected_idx
       ) s ON true
       WHERE h.id = $2 AND h.workspace_id = $1`,
      [workspaceId, hostId],
    ),
  ]);
  const first = findings.rows[0];
  const fresh = freshness.rows[0];
  return {
    findings: findings.rows.map((r) => ({
      vulnKey: r.vuln_key,
      sourcePackage: r.source_package,
      packages: r.packages,
      status: r.status,
      installedVersion: r.installed_version,
      fixedVersion: r.fixed_version,
      fixChannel: r.fix_channel,
      severity: r.severity,
      isKev: r.is_kev,
      firstSeenAt: r.first_seen_at.toISOString(),
      resolvedAt: iso(r.resolved_at),
      reopenedAt: iso(r.reopened_at),
    })),
    total: first ? Number(first.total) : 0,
    open: first ? Number(first.open_total) : 0,
    openUnfixed: first ? Number(first.open_unfixed) : 0,
    installed: installed.rows.map((r) => ({
      name: r.name,
      version: r.version,
      arch: r.arch,
      sourceName: r.source_name,
      sourceVersion: r.source_version,
      since: r.first_seen_at.toISOString(),
    })),
    freshness: {
      snapshotCollectedAt: iso(fresh?.collected_at ?? null),
      snapshotReceivedAt: iso(fresh?.received_at ?? null),
      pushIntervalSeconds: fresh?.push_interval_seconds ?? null,
    },
  };
}

export type ResolvedFindingRow = {
  kind: VulnKind;
  hostId: string;
  hostname: string;
  label: string | null;
  vulnKey: string;
  sourcePackage: string | null;
  packages: string[];
  // The version the finding was raised against, and the fix it needed.
  installedVersion: string | null;
  fixedVersion: string | null;
  severity: string | null;
  isKev: boolean;
  firstSeenAt: string;
  resolvedAt: string;
  // Image findings: the image key and its refs at the last reconcile.
  image: { id: string; os: string; arch: string; variant: string; refs: string[] } | null;
};

export type ResolvedQuery = { since: string; hostId: string | null; limit: number };

// Findings of both kinds resolved at or after `since`, newest first.
export async function getResolvedFindings(
  workspaceId: string,
  q: ResolvedQuery,
): Promise<{ rows: ResolvedFindingRow[]; total: number }> {
  if (q.hostId !== null && !isUuid(q.hostId)) return { rows: [], total: 0 };
  const { rows } = await pool.query<{
    kind: string;
    host_id: string;
    hostname: string;
    label: string | null;
    vuln_key: string;
    source_package: string | null;
    packages: string[];
    installed_version: string | null;
    fixed_version: string | null;
    severity: string | null;
    is_kev: boolean;
    first_seen_at: Date;
    resolved_at: Date;
    image_id: string | null;
    image_os: string | null;
    image_arch: string | null;
    image_variant: string | null;
    image_refs: string[];
    total: string;
  }>(
    `SELECT f.kind, h.id AS host_id, h.hostname, h.label, f.vuln_key, f.source_package,
            f.packages, f.installed_version, f.fixed_version, f.severity, f.is_kev,
            f.first_seen_at, f.resolved_at, f.image_id, f.image_os, f.image_arch,
            f.image_variant, f.image_refs,
            count(*) OVER () AS total
     FROM hosts h
     JOIN findings f ON f.host_id = h.id
     WHERE h.workspace_id = $1
       AND (($2::uuid IS NULL AND h.archived_at IS NULL) OR h.id = $2::uuid)
       AND f.kind = ANY($3::text[]) AND f.status = 'resolved'
       AND f.resolved_at >= $4::timestamptz
     ORDER BY f.resolved_at DESC, h.hostname, f.vuln_key, f.source_package
     LIMIT $5`,
    [workspaceId, q.hostId, [FINDING_KIND.package, FINDING_KIND.image], q.since, q.limit],
  );
  return {
    rows: rows.map((r) => ({
      kind: r.kind === FINDING_KIND.image ? "image" : "package",
      hostId: r.host_id,
      hostname: r.hostname,
      label: r.label,
      vulnKey: r.vuln_key,
      sourcePackage: r.source_package,
      packages: r.packages,
      installedVersion: r.installed_version,
      fixedVersion: r.fixed_version,
      severity: r.severity,
      isKev: r.is_kev,
      firstSeenAt: r.first_seen_at.toISOString(),
      resolvedAt: r.resolved_at.toISOString(),
      image:
        r.kind === FINDING_KIND.image && r.image_id !== null
          ? {
              id: r.image_id,
              os: r.image_os ?? "",
              arch: r.image_arch ?? "",
              variant: r.image_variant ?? "",
              refs: r.image_refs,
            }
          : null,
    })),
    total: rows[0] ? Number(rows[0].total) : 0,
  };
}
