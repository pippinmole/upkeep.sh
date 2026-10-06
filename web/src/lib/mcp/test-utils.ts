import type { McpViewer } from "@/lib/viewer";

import type { McpCallRecord } from "./log";
import { createRateLimiter } from "./rate-limit";
import { resolveHost, type ResolvedHost } from "./resolve";
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

// Host lookup for the host tools' tests, through the real resolveHost:
// "web-01" (or its id) is one host, "dup" names two, anything else none.
export const HOST: ResolvedHost = {
  id: "33333333-3333-4333-8333-333333333333",
  hostname: "web-01",
  label: null,
};

const DUPLICATES: ResolvedHost[] = [
  { id: "44444444-4444-4444-8444-444444444444", hostname: "dup", label: "eu" },
  { id: "55555555-5555-4555-8555-555555555555", hostname: "dup", label: null },
];

export const fakeResolveHost = (workspaceId: string, ref: string) =>
  resolveHost(workspaceId, ref, async (ws) => {
    if (ws !== WORKSPACE) return [];
    if (ref === HOST.hostname || ref === HOST.id) return [HOST];
    return ref === "dup" ? DUPLICATES : [];
  });

// Each host tool's host argument: one host resolves, an unknown or
// ambiguous one is a tool error.
export async function expectHostErrors(
  call: (host: string) => Promise<{ isError?: boolean; content: unknown }>,
) {
  const unknown = await call("nope");
  if (!unknown.isError || !resultText(unknown).includes('No host with the id or hostname "nope"'))
    throw new Error(`unknown host: ${resultText(unknown)}`);
  const dup = await call("dup");
  if (
    !dup.isError ||
    !resultText(dup).includes(`dup (eu): ${DUPLICATES[0].id}; dup: ${DUPLICATES[1].id}`)
  )
    throw new Error(`ambiguous host: ${resultText(dup)}`);
}
