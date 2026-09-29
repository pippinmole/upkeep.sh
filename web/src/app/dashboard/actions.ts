"use server";

import { randomBytes } from "crypto";
import { auth } from "@/lib/auth";
import { pool } from "@/lib/db";

// enrollment_tokens is a Next.js-owned table (user-settings-shaped, not
// agent-protocol logic), so this writes directly rather than calling Go.
// agentName (optional) becomes agents.name at enrollment; without it the
// server names the agent after the enrolling hostname.
export async function createEnrollmentToken(agentName?: string | null): Promise<string> {
  return (await issueEnrollmentToken(agentName)).token;
}

// createEnrollmentToken plus the database's issue time, which
// getEnrollmentStatus takes (so browser clock skew doesn't matter).
export async function issueEnrollmentToken(
  agentName?: string | null,
): Promise<{ token: string; issuedAt: string }> {
  const session = await auth();
  if (!session?.user?.id) throw new Error("not authenticated");

  const name = typeof agentName === "string" ? agentName.trim().slice(0, 100) : "";
  const token = randomBytes(24).toString("base64url");
  const { rows } = await pool.query<{ created_at: Date }>(
    `INSERT INTO enrollment_tokens (token, user_id, expires_at, agent_name)
     VALUES ($1, $2, now() + interval '1 hour', $3)
     RETURNING created_at`,
    [token, session.user.id, name || null],
  );
  return { token, issuedAt: rows[0].created_at.toISOString() };
}

export type EnrollmentStatus =
  | { state: "waiting" }
  | { state: "enrolled"; agentName: string }
  | { state: "reporting"; agentName: string; hostId: string; hostname: string }
  | { state: "expired" };

// Progress of a token from createEnrollmentToken, polled by the install
// panel. The server deletes the token when an agent enrolls with it
// (store.EnrollAgent), so: token row still there = waiting (or expired);
// gone = the user's first agent created since the token was issued, and
// "reporting" once that agent's first push created its host. `issuedAt` is
// issueEnrollmentToken's; it only narrows the search among the user's own
// agents.
export async function getEnrollmentStatus(
  token: string,
  issuedAt: string,
): Promise<EnrollmentStatus> {
  const session = await auth();
  if (!session?.user?.id) throw new Error("not authenticated");
  const userId = session.user.id;
  const since = new Date(issuedAt);
  if (typeof token !== "string" || Number.isNaN(since.getTime())) return { state: "expired" };

  const { rows: pending } = await pool.query<{ expired: boolean }>(
    `SELECT expires_at <= now() AS expired FROM enrollment_tokens
     WHERE token = $1 AND user_id = $2`,
    [token, userId],
  );
  if (pending[0]) return pending[0].expired ? { state: "expired" } : { state: "waiting" };

  const { rows } = await pool.query<{
    name: string;
    host_id: string | null;
    hostname: string | null;
  }>(
    `SELECT a.name, h.id AS host_id, coalesce(h.label, h.hostname) AS hostname
     FROM agents a
     LEFT JOIN LATERAL (
       SELECT hh.id, hh.label, hh.hostname
       FROM agent_hosts ah
       JOIN hosts hh ON hh.id = ah.host_id AND hh.user_id = a.user_id
       WHERE ah.agent_id = a.id
       ORDER BY ah.mode <> 'local', ah.created_at
       LIMIT 1
     ) h ON true
     WHERE a.user_id = $1 AND a.created_at >= $2::timestamptz
     ORDER BY a.created_at
     LIMIT 1`,
    [userId, since.toISOString()],
  );
  const a = rows[0];
  // Token gone and no agent: pruned after expiring.
  if (!a) return { state: "expired" };
  if (a.host_id && a.hostname) {
    return { state: "reporting", agentName: a.name, hostId: a.host_id, hostname: a.hostname };
  }
  return { state: "enrolled", agentName: a.name };
}
