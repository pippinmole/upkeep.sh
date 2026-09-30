import { pool } from "./db";
import type { Role } from "./roles";

// Settings > Members. Every user of the install is a member of its one
// workspace (docs/MEMBERS.md), so this lists the users table.
export type MemberRow = {
  id: string;
  username: string | null;
  name: string;
  email: string;
  role: Role;
  disabled: boolean;
  mustChangePassword: boolean;
  createdAt: string;
  // Newest session activity (Better Auth refreshes a session's updated_at
  // about daily while it's used), null if never signed in or signed out.
  lastActiveAt: string | null;
};

export async function getMembers(): Promise<MemberRow[]> {
  const { rows } = await pool.query<{
    id: string;
    username: string | null;
    name: string;
    email: string;
    role: Role;
    disabled: boolean;
    must_change_password: boolean;
    created_at: Date;
    last_active_at: Date | null;
  }>(
    `SELECT u.id, u.username, u.name, u.email, u.role, u.disabled_at IS NOT NULL AS disabled,
            u.must_change_password, u.created_at,
            (SELECT max(s.updated_at) FROM sessions s WHERE s.user_id = u.id) AS last_active_at
       FROM users u
      ORDER BY u.created_at, u.id`,
  );
  return rows.map((r) => ({
    id: r.id,
    username: r.username,
    name: r.name,
    email: r.email,
    role: r.role,
    disabled: r.disabled,
    mustChangePassword: r.must_change_password,
    createdAt: r.created_at.toISOString(),
    lastActiveAt: r.last_active_at?.toISOString() ?? null,
  }));
}
