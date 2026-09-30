"use server";

import { isAPIError } from "better-auth/api";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { authServer } from "@/lib/auth";

export type SignInState = { error: string | null; username?: string };

// useActionState action. Bad credentials come back as { error }; anything
// that isn't a Better Auth APIError propagates. The session cookie is set by
// the nextCookies plugin, and the redirect stays outside the try so Next's
// redirect throw is never swallowed.
export async function signInWithPassword(
  _prev: SignInState,
  formData: FormData,
): Promise<SignInState> {
  const username = String(formData.get("username") ?? "").trim();
  const password = String(formData.get("password") ?? "");
  try {
    await authServer.api.signInUsername({
      body: { username, password },
      headers: await headers(),
    });
  } catch (err) {
    if (isAPIError(err)) {
      return {
        error:
          err.body?.code === "INVALID_USERNAME_OR_PASSWORD"
            ? "Wrong username or password."
            : err.body?.code === "ACCOUNT_DISABLED"
              ? "This account is disabled. Ask an administrator."
              : "Could not sign in. Please try again.",
        username,
      };
    }
    throw err;
  }
  redirect("/dashboard");
}
