import { redirect } from "next/navigation";
import { cache } from "react";

import { auth } from "./auth";
import { pool } from "./db";
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

// The signed-in, enabled user, or null. Role and flags come from the users
// row on every request (not from the session), so a role change or a
// disable applies immediately. React-cached: one query per request.
export const getViewer = cache(async (): Promise<Viewer | null> => {
  const session = await auth();
  const id = session?.user?.id;
  if (!id) return null;
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
    [id],
  );
  const u = rows[0];
  if (!u || u.disabled || !isRole(u.role)) return null;
  return {
    userId: id,
    workspaceId: await getWorkspaceId(),
    role: u.role,
    isAdmin: u.role === "admin",
    email: u.email,
    name: u.name,
    username: u.username,
    mustChangePassword: u.must_change_password,
  };
});

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
