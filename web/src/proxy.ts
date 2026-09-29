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

export const config = {
  matcher: ["/dashboard/:path*"],
};
