import type { McpViewer } from "@/lib/viewer";

import type { McpCallRecord } from "./log";
import { createRateLimiter } from "./rate-limit";
import type { ToolContext, ToolDeps } from "./tool";

// Shared fixtures for the MCP tool tests: a member viewer, a tool context
// with a fixed dashboard base, and deps that record log rows.

export const WORKSPACE = "22222222-2222-4222-8222-222222222222";

export const testViewer: McpViewer = {
  userId: "11111111-1111-4111-8111-111111111111",
  workspaceId: WORKSPACE,
  role: "member",
  isAdmin: false,
  email: "m@example.com",
  name: "M",
  username: "m",
  mustChangePassword: false,
  credential: {
    kind: "oauth",
    clientId: "https://claude.ai/oauth/claude-code-client-metadata",
    oauthClientId: "client-row-id",
    clientName: "Claude Code",
    scopes: ["mcp:read"],
  },
};

export const BASE = "https://upkeep.example.com";

export const testCtx: ToolContext = {
  viewer: testViewer,
  dashboardUrl: (p) => `${BASE}${p}`,
};

export function testDeps() {
  const logged: McpCallRecord[] = [];
  const deps: ToolDeps = {
    log: async (call) => {
      logged.push(call);
    },
    limiter: createRateLimiter({ limit: 1000, windowMs: 60_000, now: () => 0 }),
    now: () => 0,
  };
  return { deps, logged };
}

export const resultText = (r: { content: unknown }) => (r.content as { text: string }[])[0].text;
