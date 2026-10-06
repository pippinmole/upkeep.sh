import { requireMcpAuth } from "@better-auth/mcp";
import { createMcpHandler, originValidationResponse } from "@modelcontextprotocol/server";

import { API_TOKEN_PREFIX, appBaseUrl, authServer, extraOrigins, mcpResourceUrl } from "@/lib/auth";
import { createMcpServer } from "@/lib/mcp/server";
import { bearerApiToken, getMcpApiTokenViewer, getMcpViewer, type McpViewer } from "@/lib/viewer";

// The MCP server (docs/MCP.md): stateless Streamable HTTP, one fresh server
// per request. Both protocol eras are served: 2026-07-28 requests directly,
// 2025-era ones (what most clients, Claude Code included, still send)
// through the SDK's stateless fallback.
//
// Only bearer credentials authenticate here; session cookies are stripped
// before anything reads the request, so a browser can't be tricked into
// calling a tool with the user's dashboard session. A bearer credential is
// an API token when it starts with upk_ (getMcpApiTokenViewer), otherwise
// an OAuth access token (requireMcpAuth, then getMcpViewer).

const handler = createMcpHandler(
  ({ authInfo }) => {
    const viewer = authInfo?.extra?.viewer as McpViewer | undefined;
    if (!viewer) throw new Error("mcp: request reached the server without a viewer");
    return createMcpServer(viewer);
  },
  { responseMode: "json", onerror: (err) => console.error("mcp:", err) },
);

// Origin check (MCP transport spec, against DNS rebinding of a dashboard on a
// private network): a request with an Origin header must come from the
// dashboard's own host. Clients like Claude Code send none.
function allowedOriginHosts(): string[] {
  return [appBaseUrl(), ...extraOrigins].flatMap((u) => {
    try {
      return [new URL(u).hostname];
    } catch {
      return [];
    }
  });
}

function withoutCookies(request: Request): Request {
  if (!request.headers.has("cookie")) return request;
  const headers = new Headers(request.headers);
  headers.delete("cookie");
  return new Request(request, { headers });
}

// A credential that verified but no longer maps to an enabled user who
// consents to the client, or an API token that is unknown, revoked or
// expired: answer like an invalid token, so the client signs in again
// rather than retrying.
function invalidToken(): Response {
  const resourceMetadata = `${appBaseUrl()}/.well-known/oauth-protected-resource/api/mcp`;
  return Response.json(
    { jsonrpc: "2.0", error: { code: -32000, message: "Invalid or revoked credential" }, id: null },
    {
      status: 401,
      headers: {
        "WWW-Authenticate": `Bearer error="invalid_token", resource_metadata="${resourceMetadata}"`,
      },
    },
  );
}

function serve(request: Request, viewer: McpViewer, expiresAt?: number): Promise<Response> {
  const token = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ?? "";
  return handler.fetch(request, {
    authInfo: {
      token,
      clientId: viewer.credential.clientId,
      scopes: viewer.credential.scopes,
      expiresAt,
      resource: new URL(mcpResourceUrl()),
      extra: { viewer },
    },
  });
}

async function apiTokenHandler(request: Request, token: string): Promise<Response> {
  const viewer = await getMcpApiTokenViewer(token);
  if (!viewer) {
    console.warn(`mcp: refused an API token (${token.slice(0, API_TOKEN_PREFIX.length + 8)}…)`);
    return invalidToken();
  }
  return serve(request, viewer);
}

const protectedHandler = requireMcpAuth(
  authServer,
  async (request, claims) => {
    const viewer = await getMcpViewer(claims);
    if (!viewer) {
      console.warn(
        `mcp: refused a verified token (sub ${claims.sub ?? "?"}, client ${String(claims.azp)})`,
      );
      return invalidToken();
    }
    return serve(request, viewer, claims.exp);
  },
  {
    resource: mcpResourceUrl(),
    requiredScopes: ["mcp:read"],
    // Fetch the signing keys from this process rather than through the
    // public URL, which a container may not be able to reach (hairpin NAT,
    // split DNS). Next sets PORT for `next dev`, `next start` and the
    // standalone server.
    jwksUrl: `http://127.0.0.1:${process.env.PORT ?? "3000"}/api/auth/jwks`,
  },
);

export async function POST(request: Request): Promise<Response> {
  const rejected = originValidationResponse(request, allowedOriginHosts());
  if (rejected) return rejected;
  const req = withoutCookies(request);
  const apiToken = bearerApiToken(req);
  return apiToken ? apiTokenHandler(req, apiToken) : protectedHandler(req);
}

// Stateless: there is no session stream to open (GET) or end (DELETE).
function methodNotAllowed(): Response {
  return new Response(null, { status: 405, headers: { Allow: "POST" } });
}
export const GET = methodNotAllowed;
export const DELETE = methodNotAllowed;
