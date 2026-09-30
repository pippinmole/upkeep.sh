import { pool } from "@/lib/db";

import {
  emptyGroups,
  mapAgent,
  mapContainer,
  mapFeedVuln,
  mapHost,
  mapImage,
  mapPackage,
  mapVuln,
  mergeVulns,
  type FeedVulnRow,
  type SearchResponse,
  type SearchResult,
} from "./map";
import { GROUP_LIMIT, searchTerms } from "./query";
import { type SearchGroup, feedVulnQuery, groupQuery, groupsFor } from "./sql";

// Row -> result per group. The row types are checked in map.ts.
const MAPPERS: Record<SearchGroup, (row: any) => SearchResult> = {
  vulnerabilities: mapVuln,
  packages: mapPackage,
  images: mapImage,
  containers: mapContainer,
  hosts: mapHost,
  agents: mapAgent,
};

// Runs the groups' queries in parallel for one workspace. The caller has
// already checked the viewer: search is read-only, so members and
// administrators alike may use it.
export async function runSearch(workspaceId: string, raw: string): Promise<SearchResponse> {
  const t = searchTerms(raw);
  const groups = emptyGroups();
  if (!t) return { query: raw.trim(), groups };

  const feed = feedVulnQuery(workspaceId, t);
  const [feedRows, ...results] = await Promise.all([
    feed ? pool.query<FeedVulnRow>(feed.text, feed.values).then((r) => r.rows) : [],
    ...groupsFor(t).map(async (g) => {
      const q = groupQuery(g, workspaceId, t);
      const { rows } = await pool.query(q.text, q.values);
      return [g, rows.map(MAPPERS[g])] as const;
    }),
  ]);
  for (const [g, rows] of results) groups[g] = rows;
  groups.vulnerabilities = mergeVulns(
    groups.vulnerabilities,
    feedRows.map(mapFeedVuln),
    GROUP_LIMIT,
  );
  return { query: t.q, groups };
}
