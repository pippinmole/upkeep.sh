"use server";

import { isAPIError } from "better-auth/api";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { authServer } from "@/lib/auth";
import { jsonHeaders, oauthRedirectUrl, oauthRequest } from "@/lib/oauth-query";
import { getViewer } from "@/lib/viewer";

export type ConsentState = { error: string | null };

// Allow or Deny on /oauth/consent. Better Auth checks the signed query and
// the session, records the consent on Allow, and answers with the client's
// redirect URI: with an authorization code on Allow, with
// error=access_denied on Deny.
export async function decideConsent(
  _prev: ConsentState,
  formData: FormData,
): Promise<ConsentState> {
  const oauthQuery = String(formData.get("oauth_query") ?? "");
  const accept = formData.get("decision") === "allow";
  const viewer = await getViewer();
  if (!viewer) redirect(`/login?${oauthQuery}`);
  if (viewer.mustChangePassword) {
    redirect(`/change-password?next=${encodeURIComponent(`/oauth/consent?${oauthQuery}`)}`);
  }

  let result: unknown;
  try {
    const h = jsonHeaders(await headers());
    result = await authServer.api.oauth2Consent({
      body: { accept, oauth_query: oauthQuery },
      headers: h,
      request: oauthRequest("/oauth2/consent", h),
    });
  } catch (err) {
    if (isAPIError(err)) {
      console.warn("oauth consent refused", err.body);
      return { error: consentError(err.body) };
    }
    throw err;
  }
  // Called with a Request, Better Auth answers a refusal with an error
  // Response instead of throwing.
  if (result instanceof Response && !result.ok) {
    const body = await result.json().catch(() => null);
    console.warn("oauth consent refused", body);
    return { error: consentError(body) };
  }
  const url = await oauthRedirectUrl(result);
  if (!url) return { error: consentError(null) };
  redirect(url);
}

function consentError(body: { code?: unknown; error?: unknown } | null | undefined): string {
  if (body?.error === "invalid_signature")
    return "This request has expired. Start the connection again from your app.";
  return "Could not complete the request. Start the connection again from your app.";
}
