// OAuth scopes in plain words, for the consent page (and later the
// Connected apps list). lib/auth.ts MCP_SCOPES lists the ones offered.
const SCOPE_WORDS: Record<string, string> = {
  "mcp:read": "Read your workspace's hosts, images and vulnerabilities",
  offline_access: "Stay connected without signing in again, until you revoke it",
};

export function describeScope(scope: string): string {
  return SCOPE_WORDS[scope] ?? scope;
}
