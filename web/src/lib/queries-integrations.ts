import { pool } from "./db";
import type { Viewer } from "./viewer";

// Settings > Integrations > Connected apps (docs/MCP.md#settings--integrations):
// the OAuth consents users gave MCP clients. Users all belong to the install's
// one workspace (docs/MEMBERS.md), so consents are listed from oauth_consents
// directly; administrators see everyone's, members only their own (enforced
// here, not in the UI). Last used comes from the call log, which is
// workspace data, so it is read for the viewer's workspace.
export type ConnectedAppRow = {
  id: string; // oauth_consents.id
  clientName: string; // oauth_clients.name, or the client_id when it has none
  // A CIMD client's client_id is its metadata document URL: its host says
  // who publishes the client (claude.ai for Claude Code).
  clientHost: string | null;
  userId: string | null;
  username: string | null;
  email: string | null;
  scopes: string[];
  createdAt: string;
  lastUsedAt: string | null;
};

// The host of an https client_id (a CIMD metadata URL), else null.
export function clientIdHost(clientId: string): string | null {
  if (!clientId.startsWith("https://")) return null;
  try {
    return new URL(clientId).host;
  } catch {
    return null;
  }
}

export async function getConnectedApps(viewer: Viewer): Promise<ConnectedAppRow[]> {
  const { rows } = await pool.query<{
    id: string;
    client_id: string;
    client_name: string | null;
    user_id: string | null;
    username: string | null;
    email: string | null;
    scopes: unknown;
    created_at: Date;
    last_used_at: Date | null;
  }>(
    `SELECT oc.id, oc.client_id, c.name AS client_name, oc.user_id, u.username, u.email,
            oc.scopes, oc.created_at,
            (SELECT max(m.created_at) FROM mcp_calls m
              WHERE m.workspace_id = $1 AND m.user_id = oc.user_id
                AND m.oauth_client_id = c.id) AS last_used_at
       FROM oauth_consents oc
       JOIN oauth_clients c ON c.client_id = oc.client_id
       LEFT JOIN users u ON u.id = oc.user_id
      WHERE $2::uuid IS NULL OR oc.user_id = $2
      ORDER BY oc.created_at DESC, oc.id`,
    [viewer.workspaceId, viewer.isAdmin ? null : viewer.userId],
  );
  return rows.map((r) => ({
    id: r.id,
    clientName: r.client_name || r.client_id,
    clientHost: clientIdHost(r.client_id),
    userId: r.user_id,
    username: r.username,
    email: r.email,
    scopes: Array.isArray(r.scopes) ? r.scopes.filter((s) => typeof s === "string") : [],
    createdAt: r.created_at.toISOString(),
    lastUsedAt: r.last_used_at?.toISOString() ?? null,
  }));
}

// Settings > Integrations > API tokens: the tokens users created for
// headless MCP clients (api_tokens, written by Better Auth's API key
// plugin). Administrators see everyone's, members only their own (enforced
// here, not in the UI). Never the hash: only the first characters (start).
export type ApiTokenState = "active" | "expiring" | "expired";

export type ApiTokenRow = {
  id: string; // api_tokens.id
  name: string;
  start: string | null; // upk_ plus the first characters
  userId: string;
  username: string | null;
  email: string | null;
  createdAt: string;
  lastUsedAt: string | null;
  expiresAt: string | null; // null: never
  // expiring: within EXPIRING_SOON_DAYS. An expired token stops working at
  // once; the plugin deletes it the next time a token is created or used.
  state: ApiTokenState;
};

export const EXPIRING_SOON_DAYS = 7;

export async function getApiTokens(viewer: Viewer): Promise<ApiTokenRow[]> {
  const { rows } = await pool.query<{
    id: string;
    name: string | null;
    start: string | null;
    user_id: string;
    username: string | null;
    email: string | null;
    created_at: Date;
    last_request: Date | null;
    expires_at: Date | null;
    state: ApiTokenState;
  }>(
    `SELECT t.id, t.name, t.start, t.user_id, u.username, u.email, t.created_at,
            t.last_request, t.expires_at,
            CASE WHEN t.expires_at IS NULL OR t.expires_at > now() + make_interval(days => $2)
                   THEN 'active'
                 WHEN t.expires_at > now() THEN 'expiring'
                 ELSE 'expired' END AS state
       FROM api_tokens t
       JOIN users u ON u.id = t.user_id
      WHERE $1::uuid IS NULL OR t.user_id = $1
      ORDER BY t.created_at DESC, t.id`,
    [viewer.isAdmin ? null : viewer.userId, EXPIRING_SOON_DAYS],
  );
  return rows.map((r) => ({
    id: r.id,
    name: r.name || "Unnamed token",
    start: r.start,
    userId: r.user_id,
    username: r.username,
    email: r.email,
    createdAt: r.created_at.toISOString(),
    lastUsedAt: r.last_request?.toISOString() ?? null,
    expiresAt: r.expires_at?.toISOString() ?? null,
    state: r.state,
  }));
}
