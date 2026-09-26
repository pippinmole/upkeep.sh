"use server";

import bcrypt from "bcryptjs";
import { redirect } from "next/navigation";
import { pool } from "@/lib/db";
import { signIn } from "@/lib/auth";

export async function signUp(formData: FormData) {
  const email = String(formData.get("email") ?? "")
    .toLowerCase()
    .trim();
  const password = String(formData.get("password") ?? "");
  if (!email || password.length < 8) {
    throw new Error("email and an 8+ character password are required");
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const { rows } = await pool.query(
    `INSERT INTO users (email, password_hash) VALUES ($1, $2)
     ON CONFLICT (email) DO NOTHING
     RETURNING id`,
    [email, passwordHash],
  );
  if (rows.length === 0) {
    throw new Error("an account with that email already exists");
  }

  await signIn("credentials", { email, password, redirectTo: "/dashboard" });
  redirect("/dashboard");
}
