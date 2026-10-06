import type { DataTableServerState } from "@/components/data-table/data-table";

import { pool } from "./db";
import { MCP_ACTIVITY_SORTS, type McpActivitySort } from "./mcp-activity-table";
import { isUuid } from "./queries-inventory";
import type { Viewer } from "./viewer";

// Settings > Integrations > Activity (docs/MCP.md#activity-log): the MCP
// call log, written by the web app (lib/mcp/log.ts) and pruned after 90
// days by the worker's alert_prune. Administrators see every call in the
// workspace, members only their own: the scope is applied here, in SQL,
// whatever filters the URL asks for.

export type McpCallRow = {
  id: string;
  createdAt: string;
  userId: string | null;
  username: string | null;
  email: string | null;
  credentialKind: "oauth" | "api_token";
  // The client's name at call time; the client may be gone since.
  clientName: string | null;
  tool: string;
  arguments: unknown;
  resultItems: number | null;
  durationMs: number;
  error: string | null;
};

export type McpActivityFilters = {
  q: string | null;
  userIds: string[] | null;
  // oauth_clients ids (API token ids once they exist).
  clientIds: string[] | null;
  tools: string[] | null;
  sort: { id: McpActivitySort; desc: boolean };
  page: number;
  pageSize: number;
};

const TOOL_RE = /^[a-z][a-z0-9_]{0,63}$/;

export function mcpActivityFilters(s: DataTableServerState): McpActivityFilters {
  const values = (id: string) => {
    const f = s.columnFilters.find((c) => c.id === id);
    return Array.isArray(f?.value) ? (f.value as string[]) : [];
  };
  const some = (xs: string[]) => (xs.length ? xs : null);
  const sort = s.sorting[0];
  return {
    q: s.globalFilter.trim() || null,
    userIds: some(values("user").filter(isUuid)),
    clientIds: some(values("client").filter(isUuid)),
    tools: some(values("tool").filter((t) => TOOL_RE.test(t))),
    sort:
      sort && (MCP_ACTIVITY_SORTS as readonly string[]).includes(sort.id)
        ? { id: sort.id as McpActivitySort, desc: sort.desc }
        : { id: "time", desc: true },
    page: s.pagination.pageIndex + 1,
    pageSize: s.pagination.pageSize,
  };
}

// The user whose calls a viewer may see; null = everyone's (admins).
function scopeUser(viewer: Viewer): string | null {
  return viewer.isAdmin ? null : viewer.userId;
}

export async function getMcpActivity(
  viewer: Viewer,
  f: McpActivityFilters,
): Promise<{ rows: McpCallRow[]; total: number }> {
  const dir = f.sort.desc ? "DESC" : "ASC";
  // Static ORDER BY variants (allowlisted id and direction).
  const orderBy = {
    time: `m.created_at ${dir}, m.id`,
    tool: `m.tool ${dir}, m.created_at DESC, m.id`,
    duration: `m.duration_ms ${dir}, m.created_at DESC, m.id`,
  }[f.sort.id];
  const { rows } = await pool.query<{
    id: string;
    created_at: Date;
    user_id: string | null;
    username: string | null;
    email: string | null;
    credential_kind: "oauth" | "api_token";
    client_name: string | null;
    tool: string;
    arguments: unknown;
    result_items: number | null;
    duration_ms: number;
    error: string | null;
    total: string;
  }>(
    `SELECT m.id, m.created_at, m.user_id, u.username, u.email, m.credential_kind,
            m.client_name, m.tool, m.arguments, m.result_items, m.duration_ms, m.error,
            count(*) OVER () AS total
     FROM mcp_calls m
     LEFT JOIN users u ON u.id = m.user_id
     WHERE m.workspace_id = $1
       AND ($2::uuid IS NULL OR m.user_id = $2)
       AND ($3::text IS NULL
            OR strpos(lower(m.tool), lower($3)) > 0
            OR strpos(lower(coalesce(m.client_name, '')), lower($3)) > 0
            OR strpos(lower(m.arguments::text), lower($3)) > 0
            OR strpos(lower(coalesce(m.error, '')), lower($3)) > 0)
       AND ($4::uuid[] IS NULL OR m.user_id = ANY($4))
       AND ($5::uuid[] IS NULL OR coalesce(m.oauth_client_id, m.api_token_id) = ANY($5))
       AND ($6::text[] IS NULL OR m.tool = ANY($6))
     ORDER BY ${orderBy}
     LIMIT $7 OFFSET $8`,
    [
      viewer.workspaceId,
      scopeUser(viewer),
      f.q,
      f.userIds,
      f.clientIds,
      f.tools,
      f.pageSize,
      (f.page - 1) * f.pageSize,
    ],
  );
  return {
    rows: rows.map((r) => ({
      id: r.id,
      createdAt: r.created_at.toISOString(),
      userId: r.user_id,
      username: r.username,
      email: r.email,
      credentialKind: r.credential_kind,
      clientName: r.client_name,
      tool: r.tool,
      arguments: r.arguments,
      resultItems: r.result_items,
      durationMs: r.duration_ms,
      error: r.error,
    })),
    total: Number(rows[0]?.total ?? 0),
  };
}

export type McpActivityFacets = {
  // Empty for members: they only see their own calls.
  users: { id: string; name: string; count: number }[];
  clients: { id: string; name: string; count: number }[];
  tools: { name: string; count: number }[];
};

// Facet options with counts over the calls the viewer may see.
export async function getMcpActivityFacets(viewer: Viewer): Promise<McpActivityFacets> {
  const scope = [viewer.workspaceId, scopeUser(viewer)];
  const [users, clients, tools] = await Promise.all([
    viewer.isAdmin
      ? pool.query<{ id: string; name: string; n: string }>(
          `SELECT u.id, coalesce(u.username, u.email) AS name, count(*) AS n
           FROM mcp_calls m JOIN users u ON u.id = m.user_id
           WHERE m.workspace_id = $1 AND ($2::uuid IS NULL OR m.user_id = $2)
           GROUP BY u.id ORDER BY 2`,
          scope,
        )
      : Promise.resolve({ rows: [] }),
    // Named as in the newest call, since a client's name can change.
    pool.query<{ id: string; name: string | null; n: string }>(
      `SELECT coalesce(m.oauth_client_id, m.api_token_id) AS id,
              (array_agg(m.client_name ORDER BY m.created_at DESC))[1] AS name, count(*) AS n
       FROM mcp_calls m
       WHERE m.workspace_id = $1 AND ($2::uuid IS NULL OR m.user_id = $2)
         AND coalesce(m.oauth_client_id, m.api_token_id) IS NOT NULL
       GROUP BY 1 ORDER BY 2`,
      scope,
    ),
    pool.query<{ tool: string; n: string }>(
      `SELECT m.tool, count(*) AS n
       FROM mcp_calls m
       WHERE m.workspace_id = $1 AND ($2::uuid IS NULL OR m.user_id = $2)
       GROUP BY m.tool ORDER BY m.tool`,
      scope,
    ),
  ]);
  return {
    users: users.rows.map((r) => ({ id: r.id, name: r.name, count: Number(r.n) })),
    clients: clients.rows.map((r) => ({
      id: r.id,
      name: r.name ?? "Unnamed client",
      count: Number(r.n),
    })),
    tools: tools.rows.map((r) => ({ name: r.tool, count: Number(r.n) })),
  };
}
