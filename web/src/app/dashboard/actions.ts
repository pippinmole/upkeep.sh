"use server";

import { randomBytes } from "crypto";
import { auth } from "@/lib/auth";
import { pool } from "@/lib/db";

// enrollment_tokens is a Next.js-owned table (user-settings-shaped, not
// agent-protocol logic), so this writes directly rather than calling Go.
// agentName (optional) becomes agents.name at enrollment; without it the
// server names the agent after the enrolling hostname.
export async function createEnrollmentToken(agentName?: string | null): Promise<string> {
  const session = await auth();
  if (!session?.user?.id) throw new Error("not authenticated");

  const name = typeof agentName === "string" ? agentName.trim().slice(0, 100) : "";
  const token = randomBytes(24).toString("base64url");
  await pool.query(
    `INSERT INTO enrollment_tokens (token, user_id, expires_at, agent_name)
     VALUES ($1, $2, now() + interval '1 hour', $3)`,
    [token, session.user.id, name || null],
  );
  return token;
}
