import { pool } from "./db";
import type { ImageKey } from "./image-key";

// Where a package is installed (docs/MCP.md#tools, find_package): current
// installs on the workspace's hosts and in the images on them, matched by
// binary or source name, with whether each is vulnerable: open findings
// for a host install, the image's scored vulnerabilities for an image
// package.
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

export type ImagePackageMatchRow = {
  key: ImageKey;
  // Tags and repo digests across the workspace's hosts, sorted.
  refs: string[];
  ecosystem: string;
  distro: string;
  release: string;
  name: string;
  version: string;
  arch: string;
  sourceName: string | null;
  sourceVersion: string | null;
  paths: string[];
  // Hosts with the image.
  hosts: number;
  // The image's Vulnerabilities tab rows this package belongs to
  // (image_sbom_vulns, while the list's score is current).
  vulns: number;
  kevVulns: number;
  fixableVulns: number;
  topSeverity: string | null;
};

// Packages of the effective lists (image_sbom_effective(user)) of the
// image keys on the workspace's non-archived hosts; vulnerable first, then
// by reference.
export async function findPackageInImages(
  workspaceId: string,
  q: PackageSearch,
): Promise<{ rows: ImagePackageMatchRow[]; total: number; images: number }> {
  const { rows } = await pool.query<{
    image_id: string;
    os: string;
    arch: string;
    variant: string;
    refs: string[] | null;
    ecosystem: string;
    distro: string;
    release: string;
    name: string;
    version: string;
    pkg_arch: string;
    source_name: string | null;
    source_version: string | null;
    paths: string[];
    hosts: string;
    vulns: string;
    kev: string;
    fixable: string;
    top_severity: string | null;
    total: string;
    images: string;
  }>(
    `WITH hk AS (
       SELECT hi.host_id, hi.image_id, hi.os, hi.arch, hi.variant,
              array_remove(array_remove(hi.repo_tags || hi.repo_digests, '<none>:<none>'),
                           '<none>@<none>') AS refs
       FROM hosts h
       JOIN host_images hi ON hi.host_id = h.id AND hi.removed_at IS NULL
       WHERE h.workspace_id = $1 AND h.archived_at IS NULL AND hi.os IS NOT NULL
     ),
     k AS (
       SELECT image_id, os, arch, variant, count(DISTINCT host_id) AS hosts,
              (SELECT array_agg(DISTINCT r ORDER BY r)
               FROM hk h2, unnest(h2.refs) r
               WHERE h2.image_id = hk.image_id AND h2.os = hk.os AND h2.arch = hk.arch
                 AND h2.variant = hk.variant) AS refs
       FROM hk
       GROUP BY image_id, os, arch, variant
     ),
     m AS (
       SELECT k.image_id, k.os, k.arch, k.variant, k.refs, k.hosts, e.sbom_id,
              isw.software_id, isw.paths, sv.ecosystem, sv.distro, sv.release, sv.name,
              sv.version, sv.arch AS pkg_arch, sv.source_name, sv.source_version
       FROM k
       JOIN image_sbom_effective($1) e
         ON e.image_id = k.image_id AND e.os = k.os AND e.arch = k.arch AND e.variant = k.variant
       JOIN image_software isw ON isw.sbom_id = e.sbom_id
       JOIN software_versions sv ON sv.id = isw.software_id
       WHERE (lower(sv.name) = lower($2) OR lower(sv.source_name) = lower($2))
         AND ($3::text IS NULL OR starts_with(sv.version, $3)
              OR starts_with(coalesce(sv.source_version, ''), $3))
     ),
     mv AS (
       SELECT m.*, coalesce(v.vulns, 0) AS vulns, coalesce(v.kev, 0) AS kev,
              coalesce(v.fixable, 0) AS fixable, v.top_severity, v.top_key
       FROM m
       LEFT JOIN LATERAL (
         SELECT count(*) AS vulns, count(*) FILTER (WHERE iv.is_kev) AS kev,
                count(*) FILTER (WHERE iv.fix_channel = 'standard') AS fixable,
                max(iv.severity_key) AS top_key,
                (array_agg(iv.severity ORDER BY iv.severity_key DESC))[1] AS top_severity
         FROM image_sbom_vulns iv
         JOIN image_sbom_state st ON st.id = iv.sbom_id
         JOIN image_sbom_scores sc ON sc.sbom_id = iv.sbom_id AND sc.computed_at >= st.updated_at
         WHERE iv.sbom_id = m.sbom_id AND m.software_id = ANY(iv.software_ids)
       ) v ON true
     )
     SELECT mv.*, (SELECT count(*) FROM mv) AS total,
            (SELECT count(DISTINCT (image_id, os, arch, variant)) FROM mv) AS images
     FROM mv
     ORDER BY mv.vulns = 0, mv.top_key DESC NULLS LAST, mv.refs[1] NULLS LAST, mv.image_id,
              mv.os, mv.arch, mv.variant, mv.name, mv.pkg_arch
     LIMIT $4`,
    [workspaceId, q.name, q.version, q.limit],
  );
  const first = rows[0];
  return {
    rows: rows.map((r) => ({
      key: { imageId: r.image_id, os: r.os, arch: r.arch, variant: r.variant },
      refs: r.refs ?? [],
      ecosystem: r.ecosystem,
      distro: r.distro,
      release: r.release,
      name: r.name,
      version: r.version,
      arch: r.pkg_arch,
      sourceName: r.source_name,
      sourceVersion: r.source_version,
      paths: r.paths,
      hosts: Number(r.hosts),
      vulns: Number(r.vulns),
      kevVulns: Number(r.kev),
      fixableVulns: Number(r.fixable),
      topSeverity: r.top_severity,
    })),
    total: first ? Number(first.total) : 0,
    images: first ? Number(first.images) : 0,
  };
}
