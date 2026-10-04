import { type NextRequest, NextResponse } from "next/server";

import { authServer } from "@/lib/auth";

// Next 16's proxy runs on Node, so this validates the session against the
// database (Better Auth's recommended check for Next 16) rather than only
// looking for the cookie. Pages still call auth() themselves.
export async function proxy(request: NextRequest) {
  const session = await authServer.api.getSession({ headers: request.headers });
  if (!session) {
    return NextResponse.redirect(new URL("/login", request.url));
  }
  return NextResponse.next();
}

// Only the dashboard. /api/mcp and the OAuth discovery documents under
// /.well-known must stay outside: MCP clients call them without a session
// cookie and need a 401 or the document, never a redirect to /login.
export const config = {
  matcher: ["/dashboard/:path*"],
};
