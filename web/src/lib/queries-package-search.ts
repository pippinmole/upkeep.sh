import { pool } from "./db";

// Where a package is installed (docs/MCP.md#tools, find_package): current
// installs on the workspace's hosts, matched by binary or source name,
// with whether each install has open findings. Images (image_software)
// come with the image tools.
//
// Tenancy as in queries-inventory.ts: software_versions is shared across
// workspaces and only reached through the workspace's host_software rows;
// archived hosts are left out, as on every fleet-wide read.

export type PackageInstallRow = {
  hostId: string;
  hostname: string;
  label: string | null;
  ecosystem: string;
  distro: string;
  release: string;
  name: string;
  version: string;
  arch: string;
  sourceName: string | null;
  sourceVersion: string | null;
  since: string;
  // Open host package findings this binary contributes to
  // (host_package_vuln_status).
  openFindings: number;
  kevFindings: number;
  fixableFindings: number;
  topSeverity: string | null;
};

export type PackageSearch = {
  // Binary or source package name, case-insensitive, exact.
  name: string;
  // Version prefix of the binary or source version; null = any.
  version: string | null;
  limit: number;
};

// Vulnerable installs first, then by hostname.
export async function findPackageOnHosts(
  workspaceId: string,
  q: PackageSearch,
): Promise<{ rows: PackageInstallRow[]; total: number; hosts: number }> {
  const { rows } = await pool.query<{
    host_id: string;
    hostname: string;
    label: string | null;
    ecosystem: string;
    distro: string;
    release: string;
    name: string;
    version: string;
    arch: string;
    source_name: string | null;
    source_version: string | null;
    first_seen_at: Date;
    open_findings: string | null;
    kev_count: string | null;
    fixable_count: string | null;
    top_severity: string | null;
    total: string;
    hosts: string;
  }>(
    `WITH m AS (
       SELECT h.id AS host_id, h.hostname, h.label, sv.ecosystem, sv.distro, sv.release,
              sv.name, sv.version, sv.arch, sv.source_name, sv.source_version,
              hs.first_seen_at, v.open_findings, v.kev_count, v.fixable_count, v.top_severity,
              v.top_severity_key
       FROM hosts h
       JOIN host_software hs ON hs.host_id = h.id AND hs.removed_at IS NULL
       JOIN software_versions sv ON sv.id = hs.software_id
       LEFT JOIN host_package_vuln_status v ON v.host_id = h.id AND v.software_id = sv.id
       WHERE h.workspace_id = $1 AND h.archived_at IS NULL
         AND (lower(sv.name) = lower($2) OR lower(sv.source_name) = lower($2))
         AND ($3::text IS NULL OR starts_with(sv.version, $3)
              OR starts_with(coalesce(sv.source_version, ''), $3))
     )
     SELECT m.*, (SELECT count(*) FROM m) AS total,
            (SELECT count(DISTINCT host_id) FROM m) AS hosts
     FROM m
     ORDER BY m.open_findings IS NULL, m.top_severity_key DESC NULLS LAST,
              m.hostname, m.host_id, m.name, m.arch
     LIMIT $4`,
    [workspaceId, q.name, q.version, q.limit],
  );
  const first = rows[0];
  return {
    rows: rows.map((r) => ({
      hostId: r.host_id,
      hostname: r.hostname,
      label: r.label,
      ecosystem: r.ecosystem,
      distro: r.distro,
      release: r.release,
      name: r.name,
      version: r.version,
      arch: r.arch,
      sourceName: r.source_name,
      sourceVersion: r.source_version,
      since: r.first_seen_at.toISOString(),
      openFindings: Number(r.open_findings ?? 0),
      kevFindings: Number(r.kev_count ?? 0),
      fixableFindings: Number(r.fixable_count ?? 0),
      topSeverity: r.top_severity,
    })),
    total: first ? Number(first.total) : 0,
    hosts: first ? Number(first.hosts) : 0,
  };
}
