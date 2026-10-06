import { authServer } from "@/lib/auth";

// RFC 9728 protected resource metadata for /api/mcp: names this app as the
// authorization server and lists the scopes. The mcp() plugin builds the
// document (it answers this exact path); Better Auth's handler only sees
// /api/auth/* on its own, so the route hands the request over.
export function GET(request: Request): Promise<Response> {
  return authServer.handler(request);
}
