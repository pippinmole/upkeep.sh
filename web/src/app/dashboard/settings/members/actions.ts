"use server";

import { isAPIError } from "better-auth/api";
import { revalidatePath } from "next/cache";
import type { PoolClient } from "pg";

import { asAdminAccountCreation, authServer } from "@/lib/auth";
import { pool } from "@/lib/db";
import { isRole, type Role } from "@/lib/roles";
import { ForbiddenError, requireAdmin, type Viewer } from "@/lib/viewer";

import { MEMBER_ERRORS, validateNewMember, validatePassword } from "./validation";

// Settings > Members (docs/MEMBERS.md). Admin only: every action calls
// requireAdmin first. Guard rails, checked in the database transaction that
// makes the change (with the admin rows locked, so two admins acting at
// once can't both pass):
//   - an admin can't change their own role, disable, remove or reset
//     themselves here (they change their own password from the user menu),
//     so an admin can't lock themselves out;
//   - the install always keeps at least one enabled admin.

export type MemberActionResult =
  | { ok: true }
  | { ok: false; error: string; fieldErrors?: Record<string, string> };

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const fail = (error: string): MemberActionResult => ({ ok: false, error });

async function admin(): Promise<Viewer | MemberActionResult> {
  try {
    return await requireAdmin();
  } catch (err) {
    if (err instanceof ForbiddenError) return fail(err.message);
    throw err;
  }
}

function refresh() {
  revalidatePath("/dashboard/settings/members");
}

// Runs change(client) for targetId inside a transaction with the guard
// rails around it. change returns an error message to roll back with.
async function changeMember(
  actor: Viewer,
  targetId: unknown,
  change: (client: PoolClient, targetId: string) => Promise<string | null>,
): Promise<MemberActionResult> {
  if (typeof targetId !== "string" || !UUID_RE.test(targetId)) return fail(MEMBER_ERRORS.notFound);
  if (targetId === actor.userId) return fail(MEMBER_ERRORS.self);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { rows } = await client.query<{ id: string; role: string; disabled: boolean }>(
      `SELECT id, role, disabled_at IS NOT NULL AS disabled FROM users
        WHERE role = 'admin' OR id = ANY($1::uuid[])
        ORDER BY id FOR UPDATE`,
      [[actor.userId, targetId]],
    );
    const me = rows.find((r) => r.id === actor.userId);
    if (!me || me.role !== "admin" || me.disabled) {
      await client.query("ROLLBACK");
      return fail(new ForbiddenError().message);
    }
    if (!rows.some((r) => r.id === targetId)) {
      await client.query("ROLLBACK");
      return fail(MEMBER_ERRORS.notFound);
    }
    const error = await change(client, targetId);
    if (error) {
      await client.query("ROLLBACK");
      return fail(error);
    }
    const { rows: left } = await client.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM users WHERE role = 'admin' AND disabled_at IS NULL`,
    );
    if (left[0].n < 1) {
      await client.query("ROLLBACK");
      return fail(MEMBER_ERRORS.lastAdmin);
    }
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
  refresh();
  return { ok: true };
}

export type NewMemberInput = {
  username: string;
  email: string;
  name: string;
  role: string;
  password: string;
};

// Create an account with a temporary password. The user must pick their
// own password at first sign-in (must_change_password).
export async function createMember(input: NewMemberInput): Promise<MemberActionResult> {
  const actor = await admin();
  if ("ok" in actor) return actor;
  const { member, fieldErrors } = validateNewMember(input);
  if (!member) return { ok: false, error: "Check the highlighted fields.", fieldErrors };

  let userId: string;
  try {
    // Better Auth's own sign-up (username plugin checks, password hashing,
    // credential account), allowed past the closed sign-up by
    // asAdminAccountCreation. No headers: nothing is signed in.
    const res = await asAdminAccountCreation(() =>
      authServer.api.signUpEmail({
        body: {
          email: member.email,
          password: member.password,
          name: member.name || member.username,
          username: member.username,
        },
      }),
    );
    userId = res.user.id;
  } catch (err) {
    if (isAPIError(err)) {
      const code = err.body?.code ?? "";
      const field =
        code.startsWith("USERNAME") || code === "INVALID_USERNAME" ? "username" : "email";
      const message = MEMBER_ERRORS.signUp[code] ?? "Could not create the account.";
      return { ok: false, error: message, fieldErrors: { [field]: message } };
    }
    throw err;
  }
  await pool.query(
    `UPDATE users SET role = $2, must_change_password = true, updated_at = now() WHERE id = $1`,
    [userId, member.role],
  );
  refresh();
  return { ok: true };
}

export async function setMemberRole(id: string, role: Role): Promise<MemberActionResult> {
  const actor = await admin();
  if ("ok" in actor) return actor;
  if (!isRole(role)) return fail("Unknown role.");
  return changeMember(actor, id, async (client, target) => {
    await client.query(`UPDATE users SET role = $2, updated_at = now() WHERE id = $1`, [
      target,
      role,
    ]);
    return null;
  });
}

// Set a new temporary password: the user must change it at next sign-in,
// and every session they have is signed out now.
export async function resetMemberPassword(
  id: string,
  password: string,
): Promise<MemberActionResult> {
  const actor = await admin();
  if ("ok" in actor) return actor;
  const invalid = validatePassword(password);
  if (invalid) return { ok: false, error: invalid, fieldErrors: { password: invalid } };
  const hash = await (await authServer.$context).password.hash(password);
  return changeMember(actor, id, async (client, target) => {
    const { rowCount } = await client.query(
      `UPDATE accounts SET password = $2, updated_at = now()
        WHERE user_id = $1 AND provider_id = 'credential'`,
      [target, hash],
    );
    if (rowCount === 0) {
      await client.query(
        `INSERT INTO accounts (user_id, account_id, provider_id, password)
         VALUES ($1, $1::text, 'credential', $2)`,
        [target, hash],
      );
    }
    await client.query(
      `UPDATE users SET must_change_password = true, updated_at = now() WHERE id = $1`,
      [target],
    );
    await client.query(`DELETE FROM sessions WHERE user_id = $1`, [target]);
    return null;
  });
}

// Disable: can't sign in (lib/auth.ts refuses new sessions) and is signed
// out everywhere now. Enable undoes it.
export async function setMemberDisabled(
  id: string,
  disabled: boolean,
): Promise<MemberActionResult> {
  const actor = await admin();
  if ("ok" in actor) return actor;
  if (typeof disabled !== "boolean") return fail("Invalid request.");
  return changeMember(actor, id, async (client, target) => {
    await client.query(
      `UPDATE users SET disabled_at = CASE WHEN $2 THEN COALESCE(disabled_at, now()) END,
                        updated_at = now()
        WHERE id = $1`,
      [target, disabled],
    );
    if (disabled) await client.query(`DELETE FROM sessions WHERE user_id = $1`, [target]);
    return null;
  });
}

// Remove the account (sessions and password go with it). Workspace data
// stays: it belongs to the workspace, and tokens/agents the user issued
// just lose their created_by / enrolled_by.
export async function removeMember(id: string): Promise<MemberActionResult> {
  const actor = await admin();
  if ("ok" in actor) return actor;
  return changeMember(actor, id, async (client, target) => {
    await client.query(`DELETE FROM users WHERE id = $1`, [target]);
    return null;
  });
}
