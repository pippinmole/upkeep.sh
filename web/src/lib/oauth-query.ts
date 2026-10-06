// MCP sign-in (docs/MCP.md#oauth-interactive-clients): when an OAuth client
// such as Claude Code asks to authorize and the user isn't signed in (or
// hasn't consented yet), Better Auth's OAuth provider sends the browser to
// /login or /oauth/consent with the authorization request as signed query
// parameters (`sig`, `exp`, …). The pages hand that query back to Better
// Auth as `oauth_query`, which checks the signature and continues the
// request where it left off.

export type PageSearchParams = Record<string, string | string[] | undefined>;

// The signed authorization query from a page's search params, or null when
// the page wasn't reached from an authorization request.
export function oauthQueryFrom(params: PageSearchParams): string | null {
  if (typeof params.sig !== "string") return null;
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    for (const v of Array.isArray(value) ? value : value === undefined ? [] : [value])
      q.append(key, v);
  }
  return q.toString();
}

// Where to send a user who must choose a new password first and then come
// back: only the consent page, so `next` can't become an open redirect.
export function safeReturnPath(next: string | null | undefined): string | null {
  if (!next) return null;
  return next.startsWith("/oauth/consent?") && !next.includes("\\") ? next : null;
}

// The URL Better Auth answers an OAuth step with when asked for JSON:
// { redirect: true, url } from the sign-in hook and the consent endpoint, or
// { redirect_uri }. Called with a Request, authServer.api answers with a
// Response carrying that JSON. null when there is none.
export async function oauthRedirectUrl(result: unknown): Promise<string | null> {
  if (result instanceof Response) {
    if (!result.ok) return null;
    result = await result.json().catch(() => null);
  }
  if (!result || typeof result !== "object") return null;
  const r = result as { url?: unknown; redirect_uri?: unknown };
  if (typeof r.url === "string") return r.url;
  if (typeof r.redirect_uri === "string") return r.redirect_uri;
  return null;
}

// The headers of the current request, asking Better Auth for a JSON answer
// ({ url }) instead of a redirect it would throw.
export function jsonHeaders(h: Headers): Headers {
  const out = new Headers(h);
  out.set("accept", "application/json");
  return out;
}

// The OAuth provider's authorize step refuses to run without a Request
// (server actions call Better Auth through authServer.api, which has none),
// so the actions pass one standing in for the auth endpoint they call.
export function oauthRequest(endpoint: string, h: Headers): Request {
  const base = (process.env.BETTER_AUTH_URL ?? "http://localhost:3000").replace(/\/$/, "");
  return new Request(`${base}/api/auth${endpoint}`, { method: "POST", headers: h });
}
