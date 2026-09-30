import { GROUP_LIMIT, TRIGRAM_MIN_LENGTH, type SearchTerms } from "./query";

// SQL for the global search, one statement per result group. Pure (text
// and bound values only) so the query building is unit-tested; run.ts
// executes them.
//
// Every workspace group binds the same values:
//   $1 workspace id   $2 lower-cased query (exact-match ranking)
//   $3 ILIKE "anywhere" pattern   $4 ILIKE prefix pattern   $5 group limit
// Ranking: exact match, then prefix, then anywhere; ties by the group's
// own order. Archived hosts are out of every group except Hosts, as on the
// fleet pages.
//
// Scoping and cost: every group starts from the workspace's hosts (or
// agents), so it reads only data the workspace owns. Vulnerabilities come
// from the workspace's findings, never from the CVE feed, whose tables
// hold every published CVE; the one exception is an exact advisory id,
// looked up by index (FEED_VULN_SQL). Substring matches on the two tables
// that grow with the install (software_versions, findings) use the
// trigram indexes from migration 0025.

export type SearchGroup =
  | "vulnerabilities"
  | "packages"
  | "images"
  | "containers"
  | "hosts"
  | "agents";

export type SqlQuery = { text: string; values: unknown[] };

const rank = (col: string) =>
  `CASE WHEN lower(${col}) = $2 THEN 0 WHEN ${col} ILIKE $4 THEN 1 ELSE 2 END`;

export const HOSTS_SQL = `
SELECT h.id, h.hostname, h.label, h.os_id, h.archived_at IS NOT NULL AS archived
FROM hosts h
WHERE h.workspace_id = $1 AND h.merged_into IS NULL
  AND (h.hostname ILIKE $3 OR h.label ILIKE $3)
ORDER BY h.archived_at IS NOT NULL,
         LEAST(${rank("h.hostname")}, ${rank("h.label")}),
         lower(coalesce(h.label, h.hostname)), h.id
LIMIT $5`;

export const AGENTS_SQL = `
SELECT a.id, a.name, a.platform, a.revoked_at IS NOT NULL AS revoked,
       (SELECT count(*) FROM agent_hosts ah WHERE ah.agent_id = a.id) AS hosts
FROM agents a
WHERE a.workspace_id = $1 AND a.name ILIKE $3
ORDER BY a.revoked_at IS NOT NULL, ${rank("a.name")}, lower(a.name), a.id
LIMIT $5`;

// Installed now on a current host. One row per package name (the package
// page is per name, across ecosystems). Two steps so a broad query ("lib")
// stays cheap: pick the best few names first (trigram index on
// software_versions.name, then an index probe per version for "installed on
// one of the workspace's hosts"), then count hosts and versions for those
// names only. Shorter names first among equal ranks: closer matches.
export const PACKAGES_SQL = `
WITH matched AS MATERIALIZED (
  -- Materialized so the name filter runs first, on the trigram index. Not
  -- capped: software_versions also holds image packages, which aren't in
  -- host_software, so an arbitrary first N matches could miss every
  -- package the hosts have.
  SELECT sv.id, sv.name FROM software_versions sv WHERE sv.name ILIKE $3
),
names AS (
  SELECT m.name, min(${rank("m.name")}) AS rnk
  FROM matched m
  WHERE EXISTS (SELECT 1 FROM host_software hs JOIN hosts h ON h.id = hs.host_id
                WHERE hs.software_id = m.id AND hs.removed_at IS NULL
                  AND h.workspace_id = $1 AND h.archived_at IS NULL)
  GROUP BY m.name
  ORDER BY rnk, length(m.name), m.name
  LIMIT $5
)
SELECT n.name,
       array_agg(DISTINCT sv.ecosystem ORDER BY sv.ecosystem) AS ecosystems,
       count(DISTINCT hs.host_id) AS hosts,
       count(DISTINCT sv.version) AS versions
FROM names n
JOIN software_versions sv ON sv.name = n.name
JOIN host_software hs ON hs.software_id = sv.id AND hs.removed_at IS NULL
JOIN hosts h ON h.id = hs.host_id AND h.workspace_id = $1 AND h.archived_at IS NULL
GROUP BY n.name, n.rnk
ORDER BY n.rnk, length(n.name), n.name`;

// Image repositories present on a current host, from repo tags (and repo
// digests for images pulled by digest only), split as on the fleet Images
// page (queries-docker-fleet.ts REFS_CTE).
export const IMAGES_SQL = `
WITH refs AS (
  SELECT hi.host_id,
         regexp_replace(t, ':[^:/]+$', '') AS repo,
         substring(t FROM ':([^:/]+)$') AS tag
  FROM hosts h
  JOIN host_images hi ON hi.host_id = h.id AND hi.removed_at IS NULL
  CROSS JOIN LATERAL unnest(hi.repo_tags) t
  WHERE h.workspace_id = $1 AND h.archived_at IS NULL AND t <> '<none>:<none>'
  UNION ALL
  SELECT hi.host_id, split_part(d, '@', 1), NULL
  FROM hosts h
  JOIN host_images hi ON hi.host_id = h.id AND hi.removed_at IS NULL
  CROSS JOIN LATERAL unnest(hi.repo_digests) d
  WHERE h.workspace_id = $1 AND h.archived_at IS NULL AND d <> '<none>@<none>'
)
SELECT repo,
       count(DISTINCT host_id) AS hosts,
       (array_agg(DISTINCT tag) FILTER (WHERE tag IS NOT NULL))[1:4] AS tags
FROM refs
WHERE repo <> '' AND (repo ILIKE $3 OR tag ILIKE $3 OR repo || ':' || tag ILIKE $3)
GROUP BY repo
ORDER BY min(LEAST(${rank("repo")}, ${rank("repo || ':' || coalesce(tag, '')")})),
         count(DISTINCT host_id) DESC, repo
LIMIT $5`;

// Current containers (any state) on current hosts, by name.
export const CONTAINERS_SQL = `
SELECT c.host_id, h.hostname, h.label, c.container_id, c.name, c.image, c.state
FROM hosts h
JOIN host_containers c ON c.host_id = h.id AND c.removed_at IS NULL
WHERE h.workspace_id = $1 AND h.archived_at IS NULL
  AND (c.name ILIKE $3 OR c.compose_service ILIKE $3)
ORDER BY ${rank("c.name")}, c.state = 'running' DESC, lower(c.name), h.hostname, c.container_id
LIMIT $5`;

// Vulnerabilities with a finding (open or resolved) on a current host,
// matched on the vuln key: a CVE id, or an advisory id when there is none
// (DSA-5532-1). Reads only the workspace's findings; ILIKE '%q%' on
// vuln_key uses findings_vuln_key_trgm_idx (migration 0025) from 3
// characters. Advisory aliases (USN / DSA ids citing a CVE) are matched by
// FEED_VULN_SQL on the exact id instead: a substring of an array can't use
// an index.
//
// Two steps, as for packages: rank the matching keys with cheap aggregates
// (a query like "cve-2" matches every finding), then describe the top few
// through findings_vuln_key_idx.
export const VULNS_SQL = `
WITH keys AS (
  SELECT f.vuln_key, min(${rank("f.vuln_key")}) AS rnk,
         bool_or(f.status = 'open') AS any_open, max(f.severity_key) AS top_key
  FROM hosts h
  JOIN findings f ON f.host_id = h.id
  WHERE h.workspace_id = $1 AND h.archived_at IS NULL
    AND f.kind IN ('vulnerable_package', 'vulnerable_image')
    AND f.vuln_key IS NOT NULL AND f.vuln_key ILIKE $3
  GROUP BY f.vuln_key
  ORDER BY rnk, any_open DESC, top_key DESC, f.vuln_key
  LIMIT $5
)
SELECT k.vuln_key,
       (array_agg(f.severity ORDER BY f.severity_key DESC))[1] AS severity,
       bool_or(f.is_kev) AS is_kev,
       count(DISTINCT f.host_id) FILTER (WHERE f.status = 'open') AS open_hosts
FROM keys k
JOIN findings f ON f.vuln_key = k.vuln_key
JOIN hosts h ON h.id = f.host_id AND h.workspace_id = $1 AND h.archived_at IS NULL
WHERE f.kind IN ('vulnerable_package', 'vulnerable_image')
GROUP BY k.vuln_key, k.rnk, k.any_open, k.top_key
ORDER BY k.rnk, k.any_open DESC, k.top_key DESC, k.vuln_key`;

// An exact advisory id (CVE-2024-3094, USN-6700-1, GHSA-…), looked up in
// the whole feed, whether or not it affects the workspace: point lookups on
// cves_pkey, advisories_pkey, advisories_vuln_key_idx and the GIN
// advisories_cve_ids_idx, never a scan of the feed. An advisory id resolves
// to the vuln key(s) its page lives under. Each key carries the
// workspace's findings for it (findings_vuln_key_idx), so an alias typed
// in full still says "open on 2 hosts".
//   $1 the canonical id   $2 workspace id
export const FEED_VULN_SQL = `
WITH cited AS MATERIALIZED (
  -- No LIMIT / EXISTS here: with one, the planner bets on finding a row
  -- early and scans advisories instead of using the GIN index.
  SELECT a.id FROM advisories a WHERE a.cve_ids @> ARRAY[$1]::text[]
),
keys AS (
  SELECT id AS vuln_key, NULL::text AS via FROM cves WHERE id = $1
  UNION
  SELECT $1, NULL
  WHERE EXISTS (SELECT 1 FROM advisories a WHERE a.vuln_key = $1)
     OR EXISTS (SELECT 1 FROM cited)
  UNION
  SELECT a.vuln_key, a.id FROM advisories a WHERE a.id = $1 AND a.vuln_key <> $1
)
SELECT k.vuln_key, min(k.via) AS via_advisory,
       bool_or(coalesce(c.is_kev, false)) AS is_kev,
       max(c.cvss_v3_score)::float8 AS cvss_v3_score,
       left(min(c.description), 160) AS description,
       min(w.severity) AS severity,
       coalesce(max(w.open_hosts), 0) AS open_hosts,
       coalesce(max(w.findings), 0) AS findings
FROM keys k
LEFT JOIN cves c ON c.id = k.vuln_key
LEFT JOIN LATERAL (
  SELECT (array_agg(f.severity ORDER BY f.severity_key DESC))[1] AS severity,
         count(DISTINCT f.host_id) FILTER (WHERE f.status = 'open') AS open_hosts,
         count(*) AS findings
  FROM findings f
  JOIN hosts h ON h.id = f.host_id
  WHERE f.vuln_key = k.vuln_key AND h.workspace_id = $2 AND h.archived_at IS NULL
    AND f.kind IN ('vulnerable_package', 'vulnerable_image')
) w ON true
GROUP BY k.vuln_key
ORDER BY k.vuln_key
LIMIT 3`;

const GROUP_SQL: Record<SearchGroup, string> = {
  vulnerabilities: VULNS_SQL,
  packages: PACKAGES_SQL,
  images: IMAGES_SQL,
  containers: CONTAINERS_SQL,
  hosts: HOSTS_SQL,
  agents: AGENTS_SQL,
};

export const SEARCH_GROUPS = Object.keys(GROUP_SQL) as SearchGroup[];

// Matched on the trigram indexes of migration 0025.
const TRIGRAM_GROUPS: ReadonlySet<SearchGroup> = new Set(["vulnerabilities", "packages"]);

// The groups worth querying for these terms: all of them from
// TRIGRAM_MIN_LENGTH characters, the small per-workspace ones below it.
export function groupsFor(t: SearchTerms): SearchGroup[] {
  return t.q.length >= TRIGRAM_MIN_LENGTH
    ? SEARCH_GROUPS
    : SEARCH_GROUPS.filter((g) => !TRIGRAM_GROUPS.has(g));
}

export function groupQuery(
  group: SearchGroup,
  workspaceId: string,
  t: SearchTerms,
  limit = GROUP_LIMIT,
): SqlQuery {
  return {
    text: GROUP_SQL[group],
    values: [workspaceId, t.lower, t.contains, t.prefix, limit],
  };
}

// Null unless the query is an exact advisory id.
export function feedVulnQuery(workspaceId: string, t: SearchTerms): SqlQuery | null {
  return t.vulnId ? { text: FEED_VULN_SQL, values: [t.vulnId, workspaceId] } : null;
}
