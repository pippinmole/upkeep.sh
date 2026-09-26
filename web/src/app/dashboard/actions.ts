"use server";

import { randomBytes } from "crypto";
import { auth } from "@/lib/auth";
import { pool } from "@/lib/db";

// enrollment_tokens is a Next.js-owned table (user-settings-shaped, not
// agent-protocol logic), so this writes directly rather than calling Go.
export async function createEnrollmentToken(): Promise<string> {
  const session = await auth();
  if (!session?.user?.id) throw new Error("not authenticated");

  const token = randomBytes(24).toString("base64url");
  await pool.query(
    `INSERT INTO enrollment_tokens (token, user_id, expires_at)
     VALUES ($1, $2, now() + interval '1 hour')`,
    [token, session.user.id],
  );
  return token;
}
