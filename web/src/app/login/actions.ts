"use server";

import { isAPIError } from "better-auth/api";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { authServer } from "@/lib/auth";
import { jsonHeaders, oauthRedirectUrl, oauthRequest } from "@/lib/oauth-query";

export type SignInState = { error: string | null; username?: string };

// useActionState action. Bad credentials come back as { error }; anything
// that isn't a Better Auth APIError propagates. The session cookie is set by
// the nextCookies plugin, and the redirect stays outside the try so Next's
// redirect throw is never swallowed.
//
// With an oauth_query (an MCP client's authorization request, see
// lib/oauth-query.ts), the OAuth provider's sign-in hook checks its signature
// and continues the request: the answer is the consent page, or the client's
// redirect URI when the user already consented.
export async function signInWithPassword(
  _prev: SignInState,
  formData: FormData,
): Promise<SignInState> {
  const username = String(formData.get("username") ?? "").trim();
  const password = String(formData.get("password") ?? "");
  const oauthQuery = String(formData.get("oauth_query") ?? "");
  let result: unknown;
  try {
    const h = oauthQuery ? jsonHeaders(await headers()) : await headers();
    result = await authServer.api.signInUsername({
      // oauth_query isn't in the endpoint's own schema; the provider's hook
      // reads it from the body.
      body: { username, password, ...(oauthQuery ? { oauth_query: oauthQuery } : {}) },
      headers: h,
      // Continuing the authorization request needs a Request to read.
      ...(oauthQuery ? { request: oauthRequest("/sign-in/username", h) } : {}),
    });
  } catch (err) {
    if (isAPIError(err)) {
      return {
        error:
          err.body?.code === "INVALID_USERNAME_OR_PASSWORD"
            ? "Wrong username or password."
            : err.body?.code === "ACCOUNT_DISABLED"
              ? "This account is disabled. Ask an administrator."
              : err.body?.error === "invalid_signature"
                ? "This sign-in link has expired. Start the connection again from your app."
                : "Could not sign in. Please try again.",
        username,
      };
    }
    throw err;
  }
  if (!oauthQuery) redirect("/dashboard");
  const next = await oauthRedirectUrl(result);
  if (!next) {
    return {
      error:
        "Signed in, but the connection request could not continue. Start it again from your app.",
      username,
    };
  }
  redirect(next);
}
