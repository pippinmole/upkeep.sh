"use server";

import { isAPIError } from "better-auth/api";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { authServer } from "@/lib/auth";
import { pool } from "@/lib/db";
import { safeReturnPath } from "@/lib/oauth-query";
import { getViewer } from "@/lib/viewer";

export type ChangePasswordState = { error: string | null };

// Any signed-in user changes their own password here, and a user whose
// password was set by an administrator (must_change_password) is sent here
// before anything else. Better Auth checks the current password; other
// sessions are signed out.
export async function changePassword(
  _prev: ChangePasswordState,
  formData: FormData,
): Promise<ChangePasswordState> {
  const viewer = await getViewer();
  if (!viewer) redirect("/login");
  const currentPassword = String(formData.get("currentPassword") ?? "");
  const newPassword = String(formData.get("newPassword") ?? "");
  const confirm = String(formData.get("confirmPassword") ?? "");
  if (newPassword.length < 8) return { error: "Use at least 8 characters for the new password." };
  if (newPassword.length > 128) return { error: "That password is too long." };
  if (newPassword !== confirm) return { error: "The new passwords don't match." };
  if (newPassword === currentPassword) {
    return { error: "Choose a password different from the current one." };
  }

  try {
    await authServer.api.changePassword({
      body: { currentPassword, newPassword, revokeOtherSessions: true },
      headers: await headers(),
    });
  } catch (err) {
    if (isAPIError(err)) {
      return {
        error:
          err.body?.code === "INVALID_PASSWORD"
            ? "The current password is wrong."
            : "Could not change the password. Please try again.",
      };
    }
    throw err;
  }
  await pool.query(
    `UPDATE users SET must_change_password = false, updated_at = now() WHERE id = $1`,
    [viewer.userId],
  );
  // Back to the OAuth consent page when an MCP sign-in sent the user here.
  redirect(safeReturnPath(String(formData.get("next") ?? "")) ?? "/dashboard");
}
