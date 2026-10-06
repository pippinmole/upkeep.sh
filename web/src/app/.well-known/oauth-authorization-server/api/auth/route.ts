import { oauthProviderAuthServerMetadata } from "@better-auth/oauth-provider";

import { authServer } from "@/lib/auth";

// RFC 8414 authorization server metadata. The issuer is Better Auth's base
// URL (<BETTER_AUTH_URL>/api/auth), so the document lives at the
// issuer-derived path /.well-known/oauth-authorization-server/api/auth,
// which is where MCP clients look first.
export const GET = oauthProviderAuthServerMetadata(authServer);
