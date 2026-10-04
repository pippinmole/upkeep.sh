/// <reference types="bun" />

import { describe, expect, test } from "bun:test";
import * as z from "zod";

import type { McpViewer } from "@/lib/viewer";

import type { McpCallRecord } from "./log";
import { createRateLimiter } from "./rate-limit";
import {
  defineTool,
  RATE_LIMITED_MESSAGE,
  TEMPORARY_PASSWORD_MESSAGE,
  ToolError,
  type ToolContext,
  type ToolDeps,
} from "./tool";

const viewer: McpViewer = {
  userId: "11111111-1111-4111-8111-111111111111",
  workspaceId: "22222222-2222-4222-8222-222222222222",
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

const ctx = (over: Partial<McpViewer> = {}): ToolContext => ({
  viewer: { ...viewer, ...over },
  dashboardUrl: (p) => `https://upkeep.example.com${p}`,
});

function deps(limit = 100) {
  const logged: McpCallRecord[] = [];
  let t = 1000;
  const d: ToolDeps = {
    log: async (call) => {
      logged.push(call);
    },
    limiter: createRateLimiter({ limit, windowMs: 60_000, now: () => 0 }),
    now: () => (t += 5),
  };
  return { d, logged };
}

const listHosts = defineTool({
  name: "list_things",
  title: "Things",
  description: "Lists things",
  input: z.object({ limit: z.number().int().min(1).max(100).default(15) }),
  output: z.object({
    items: z.array(z.object({ name: z.string(), dashboard_url: z.string() })),
    truncated: z.boolean(),
  }),
  async run({ limit }, { dashboardUrl }) {
    if (limit === 13) throw new ToolError("No host named web-13.");
    if (limit === 66) throw new Error("connection refused");
    if (limit === 99) return { items: "nope" } as never;
    return {
      items: Array.from({ length: Math.min(limit, 2) }, (_, i) => ({
        name: `host-${i}`,
        dashboard_url: dashboardUrl(`/dashboard/hosts/${i}`),
      })),
      truncated: false,
    };
  },
  render: (r) => r.items.map((i) => i.name).join(", "),
  countItems: (r) => r.items.length,
});

const text = (r: { content: unknown }) => (r.content as { text: string }[])[0].text;

describe("defineTool", () => {
  test("structured content, a text rendering, dashboard links and a log row", async () => {
    const { d, logged } = deps();
    const res = await listHosts.call({ limit: 5 }, ctx(), d);
    expect(res.isError).toBeUndefined();
    expect(res.structuredContent).toEqual({
      items: [
        { name: "host-0", dashboard_url: "https://upkeep.example.com/dashboard/hosts/0" },
        { name: "host-1", dashboard_url: "https://upkeep.example.com/dashboard/hosts/1" },
      ],
      truncated: false,
    });
    expect(text(res)).toBe("host-0, host-1");
    expect(logged).toEqual([
      {
        viewer: ctx().viewer,
        tool: "list_things",
        arguments: { limit: 5 },
        resultItems: 2,
        durationMs: 5,
        error: null,
      },
    ]);
  });

  test("defaults from the input schema are applied and logged", async () => {
    const { d, logged } = deps();
    await listHosts.call(undefined, ctx(), d);
    expect(logged[0].arguments).toEqual({ limit: 15 });
  });

  test("invalid arguments: a tool error naming the field, logged", async () => {
    const { d, logged } = deps();
    const res = await listHosts.call({ limit: 500 }, ctx(), d);
    expect(res.isError).toBe(true);
    expect(text(res)).toStartWith("Invalid arguments: limit:");
    expect(logged[0]).toMatchObject({ arguments: { limit: 500 }, resultItems: null });
    expect(logged[0].error).toStartWith("Invalid arguments");
  });

  test("a ToolError's message reaches the client", async () => {
    const { d, logged } = deps();
    const res = await listHosts.call({ limit: 13 }, ctx(), d);
    expect(res).toEqual({
      isError: true,
      content: [{ type: "text", text: "No host named web-13." }],
    });
    expect(logged[0].error).toBe("No host named web-13.");
  });

  test("other errors are hidden from the client but logged", async () => {
    const { d, logged } = deps();
    const res = await listHosts.call({ limit: 66 }, ctx(), d);
    expect(res.isError).toBe(true);
    expect(text(res)).not.toContain("connection refused");
    expect(logged[0].error).toBe("connection refused");
  });

  test("a result that doesn't match the output schema is an internal error", async () => {
    const { d, logged } = deps();
    const res = await listHosts.call({ limit: 99 }, ctx(), d);
    expect(res.isError).toBe(true);
    expect(res.structuredContent).toBeUndefined();
    expect(logged[0].error).not.toBeNull();
  });

  test("a temporary password: refused with the change-password message, logged", async () => {
    const { d, logged } = deps();
    const res = await listHosts.call({ limit: 5 }, ctx({ mustChangePassword: true }), d);
    expect(res.isError).toBe(true);
    expect(text(res)).toBe(TEMPORARY_PASSWORD_MESSAGE);
    expect(logged[0].error).toBe(TEMPORARY_PASSWORD_MESSAGE);
  });

  test("the call still returns when logging fails", async () => {
    const { d } = deps();
    d.log = async () => {
      throw new Error("db down");
    };
    const res = await listHosts.call({ limit: 5 }, ctx(), d);
    expect(res.isError).toBeUndefined();
    expect(text(res)).toBe("host-0, host-1");
  });

  test("the rate limit: a tool error, per credential, not logged", async () => {
    const { d, logged } = deps(2);
    await listHosts.call({}, ctx(), d);
    await listHosts.call({}, ctx(), d);
    const limited = await listHosts.call({}, ctx(), d);
    expect(limited).toEqual({
      isError: true,
      content: [{ type: "text", text: RATE_LIMITED_MESSAGE }],
    });
    expect(logged).toHaveLength(2);
    // Another user (another credential) has its own budget.
    const other = await listHosts.call(
      {},
      ctx({ userId: "33333333-3333-4333-8333-333333333333" }),
      d,
    );
    expect(other.isError).toBeUndefined();
  });
});
