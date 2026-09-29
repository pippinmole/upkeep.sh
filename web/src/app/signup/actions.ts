"use server";

import bcrypt from "bcryptjs";
import { pool } from "@/lib/db";
import { signIn } from "@/lib/auth";

export type SignUpState = { error: string | null; email?: string };

// useActionState action: validation problems come back as { error } for
// the form to show inline. On success signIn throws Next's redirect, which
// must propagate (never catch it).
export async function signUp(_prev: SignUpState, formData: FormData): Promise<SignUpState> {
  const email = String(formData.get("email") ?? "")
    .toLowerCase()
    .trim();
  const password = String(formData.get("password") ?? "");
  if (!email) return { error: "Enter your email address." };
  if (password.length < 8) return { error: "Use at least 8 characters for the password.", email };

  const passwordHash = await bcrypt.hash(password, 12);
  const { rows } = await pool.query(
    `INSERT INTO users (email, password_hash) VALUES ($1, $2)
     ON CONFLICT (email) DO NOTHING
     RETURNING id`,
    [email, passwordHash],
  );
  if (rows.length === 0) {
    return { error: "An account with that email already exists. Sign in instead.", email };
  }

  await signIn("credentials", { email, password, redirectTo: "/dashboard" });
  return { error: null };
}
