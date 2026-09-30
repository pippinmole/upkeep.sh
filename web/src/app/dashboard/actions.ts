"use server";

import { randomBytes } from "crypto";
import { resolveAgentImage } from "@/lib/agent-image";
import { requireAdmin } from "@/lib/viewer";
import { pool } from "@/lib/db";

// enrollment_tokens is a Next.js-owned table (user-settings-shaped, not
// agent-protocol logic), so this writes directly rather than calling Go.
// agentName (optional) becomes agents.name at enrollment; without it the
// server names the agent after the enrolling hostname.
export async function createEnrollmentToken(agentName?: string | null): Promise<string> {
  return (await issueEnrollmentToken(agentName)).token;
}

// createEnrollmentToken plus the database's issue time, which
// getEnrollmentStatus takes (so browser clock skew doesn't matter), and
// the agent image for the install command (lib/agent-image.ts, resolved
// here on the server so SW_AGENT_IMAGE works at runtime).
export async function issueEnrollmentToken(
  agentName?: string | null,
): Promise<{ token: string; issuedAt: string; agentImage: string }> {
  const { userId, workspaceId } = await requireAdmin();

  const name = typeof agentName === "string" ? agentName.trim().slice(0, 100) : "";
  const token = randomBytes(24).toString("base64url");
  const { rows } = await pool.query<{ created_at: Date }>(
    `INSERT INTO enrollment_tokens (token, workspace_id, created_by, expires_at, agent_name)
     VALUES ($1, $2, $3, now() + interval '1 hour', $4)
     RETURNING created_at`,
    [token, workspaceId, userId, name || null],
  );
  return { token, issuedAt: rows[0].created_at.toISOString(), agentImage: resolveAgentImage() };
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
  const { workspaceId } = await requireAdmin();
  const since = new Date(issuedAt);
  if (typeof token !== "string" || Number.isNaN(since.getTime())) return { state: "expired" };

  const { rows: pending } = await pool.query<{ expired: boolean }>(
    `SELECT expires_at <= now() AS expired FROM enrollment_tokens
     WHERE token = $1 AND workspace_id = $2`,
    [token, workspaceId],
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
       JOIN hosts hh ON hh.id = ah.host_id AND hh.workspace_id = a.workspace_id
       WHERE ah.agent_id = a.id
       ORDER BY ah.mode <> 'local', ah.created_at
       LIMIT 1
     ) h ON true
     WHERE a.workspace_id = $1 AND a.created_at >= $2::timestamptz
     ORDER BY a.created_at
     LIMIT 1`,
    [workspaceId, since.toISOString()],
  );
  const a = rows[0];
  // Token gone and no agent: pruned after expiring.
  if (!a) return { state: "expired" };
  if (a.host_id && a.hostname) {
    return { state: "reporting", agentName: a.name, hostId: a.host_id, hostname: a.hostname };
  }
  return { state: "enrolled", agentName: a.name };
}
