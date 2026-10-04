import { redirect } from "next/navigation";
import { cache } from "react";

import { auth } from "./auth";
import { pool } from "./db";
import { isUuid } from "./queries-inventory";
import { ADMIN_ONLY_MESSAGE, isRole, type Role } from "./roles";

// Who is looking, and at which workspace (docs/MEMBERS.md).
//
// An install has one workspace (server/migrations/0023_members): every signed-in
// user reads the same hosts, agents, channels, rules and reports, and every
// query is scoped by viewer.workspaceId. Writes additionally need the admin
// role: every mutating server action and route handler calls requireAdmin()
// before touching the database. Hiding controls in the UI is only the UX
// layer.

export type Viewer = {
  userId: string;
  workspaceId: string;
  role: Role;
  isAdmin: boolean;
  email: string;
  name: string;
  username: string | null;
  mustChangePassword: boolean;
};

// The install's workspace. There is exactly one in a real install; the Go
// integration tests create more in their own database, so pick the oldest
// rather than assuming a single row. Resolved once per server process.
let workspaceIdPromise: Promise<string> | null = null;
export function getWorkspaceId(): Promise<string> {
  workspaceIdPromise ??= pool
    .query<{ id: string }>(`SELECT id FROM workspaces ORDER BY created_at, id LIMIT 1`)
    .then(({ rows }) => {
      if (!rows[0]) throw new Error("no workspace: run the database migrations (0023_members)");
      return rows[0].id;
    })
    .catch((err) => {
      workspaceIdPromise = null;
      throw err;
    });
  return workspaceIdPromise;
}

// The enabled user with this id as a Viewer, or null when the user is
// unknown or disabled. Role and flags come from the users row on every call
// (never from a session or a token), so a role change or a disable applies
// on the next request. Shared by the dashboard (session cookie, getViewer)
// and /api/mcp (bearer credential, getMcpViewer) so the two can't drift.
export async function viewerForUser(userId: string): Promise<Viewer | null> {
  const { rows } = await pool.query<{
    role: string;
    must_change_password: boolean;
    disabled: boolean;
    email: string;
    name: string;
    username: string | null;
  }>(
    `SELECT role, must_change_password, disabled_at IS NOT NULL AS disabled, email, name, username
       FROM users WHERE id = $1`,
    [userId],
  );
  const u = rows[0];
  if (!u || u.disabled || !isRole(u.role)) return null;
  return {
    userId,
    workspaceId: await getWorkspaceId(),
    role: u.role,
    isAdmin: u.role === "admin",
    email: u.email,
    name: u.name,
    username: u.username,
    mustChangePassword: u.must_change_password,
  };
}

// The signed-in, enabled user, or null. React-cached: one query per request.
export const getViewer = cache(async (): Promise<Viewer | null> => {
  const session = await auth();
  const id = session?.user?.id;
  if (!id) return null;
  return viewerForUser(id);
});

// The credential an /api/mcp call was made with (docs/MCP.md#the-mcp-viewer).
// OAuth only for now; API tokens (credential kind api_token) come later.
export type McpCredential = {
  kind: "oauth";
  clientId: string; // the OAuth client_id (a CIMD client's metadata URL)
  oauthClientId: string; // oauth_clients.id, which mcp_calls references
  clientName: string | null;
  scopes: string[];
};

export type McpViewer = Viewer & { credential: McpCredential };

// The verified claims of an OAuth access token as requireMcpAuth hands them
// over (signature, issuer, audience and expiry already checked).
export type McpAccessTokenClaims = { sub?: string; azp?: unknown; scope?: unknown };

// /api/mcp: the Viewer behind a verified bearer credential, or null (the
// route answers 401, so the client signs in again) when the user is unknown
// or disabled, the client is gone or disabled, or the user no longer
// consents to the client. The consent check makes revoking a connected app
// take effect on the next call rather than when the access token expires.
// A user on a temporary password still resolves (mustChangePassword): the
// tools refuse with a message telling them to choose a password first.
export async function getMcpViewer(claims: McpAccessTokenClaims): Promise<McpViewer | null> {
  const userId = claims.sub;
  const clientId = typeof claims.azp === "string" ? claims.azp : null;
  if (!userId || !isUuid(userId) || !clientId) return null;
  const [viewer, client] = await Promise.all([
    viewerForUser(userId),
    pool.query<{ id: string; name: string | null }>(
      `SELECT c.id, c.name
         FROM oauth_clients c
        WHERE c.client_id = $1 AND NOT coalesce(c.disabled, false)
          AND EXISTS (SELECT 1 FROM oauth_consents oc
                       WHERE oc.client_id = c.client_id AND oc.user_id = $2)`,
      [clientId, userId],
    ),
  ]);
  const c = client.rows[0];
  if (!viewer || !c) return null;
  const scopes = typeof claims.scope === "string" ? claims.scope.split(" ").filter(Boolean) : [];
  return {
    ...viewer,
    credential: { kind: "oauth", clientId, oauthClientId: c.id, clientName: c.name, scopes },
  };
}

// Pages and layouts: the viewer, or a redirect to sign in (or to pick a new
// password first, after an admin set a temporary one).
export async function requireViewer(): Promise<Viewer> {
  const viewer = await getViewer();
  if (!viewer) redirect("/login");
  if (viewer.mustChangePassword) redirect("/change-password");
  return viewer;
}

// Thrown by requireAdmin / requireActionViewer. Server actions let it
// propagate (the UI never offers these actions to members) or turn it into
// their own { ok: false } result.
export class ForbiddenError extends Error {
  constructor(message = ADMIN_ONLY_MESSAGE) {
    super(message);
    this.name = "ForbiddenError";
  }
}

// Server actions and route handlers that only read: any signed-in viewer
// who isn't still on a temporary password.
export async function requireActionViewer(): Promise<Viewer> {
  const viewer = await getViewer();
  if (!viewer) throw new ForbiddenError("You are not signed in.");
  if (viewer.mustChangePassword) throw new ForbiddenError("Choose a new password first.");
  return viewer;
}

// Every server action or route handler that writes: an admin, or throws.
export async function requireAdmin(): Promise<Viewer> {
  const viewer = await requireActionViewer();
  if (!viewer.isAdmin) throw new ForbiddenError();
  return viewer;
}
