/// <reference types="bun" />

import { beforeEach, describe, expect, mock, test } from "bun:test";

import type { DataTableServerState } from "@/components/data-table/data-table";

import type { Viewer } from "./viewer";

// getMcpActivity / getMcpActivityFacets against a fake pool: the SQL is
// the real module's; the test checks what it is bound to, so a member's
// scope can't be widened by the URL's filters.

let calls: { sql: string; params: unknown[] }[];
const query = mock(async (sql: string, params: unknown[] = []) => {
  calls.push({ sql, params });
  return { rows: [] };
});
mock.module("./db", () => ({ pool: { query } }));

const { getMcpActivity, getMcpActivityFacets, mcpActivityFilters } =
  await import("./queries-mcp-activity");

const WORKSPACE = "22222222-2222-4222-8222-222222222222";
const ME = "11111111-1111-4111-8111-111111111111";
const OTHER = "33333333-3333-4333-8333-333333333333";
const CLIENT = "44444444-4444-4444-8444-444444444444";

const viewer = (isAdmin: boolean): Viewer =>
  ({
    userId: ME,
    workspaceId: WORKSPACE,
    role: isAdmin ? "admin" : "member",
    isAdmin,
    email: "m@example.com",
    name: "M",
    username: "m",
    mustChangePassword: false,
  }) as Viewer;

function state(over: Partial<DataTableServerState> = {}): DataTableServerState {
  return {
    sorting: [{ id: "time", desc: true }],
    pagination: { pageIndex: 0, pageSize: 50 },
    globalFilter: "",
    columnFilters: [],
    ...over,
  };
}

beforeEach(() => {
  calls = [];
});

describe("mcpActivityFilters", () => {
  test("keeps ids, tool names and the sort to their allowlists", () => {
    expect(
      mcpActivityFilters(
        state({
          globalFilter: "  web-01 ",
          sorting: [{ id: "arguments", desc: false }],
          pagination: { pageIndex: 2, pageSize: 20 },
          columnFilters: [
            { id: "user", value: [OTHER, "not-a-uuid"] },
            { id: "client", value: ["x", CLIENT] },
            { id: "tool", value: ["get_host", "DROP TABLE", "list_hosts"] },
          ],
        }),
      ),
    ).toEqual({
      q: "web-01",
      userIds: [OTHER],
      clientIds: [CLIENT],
      tools: ["get_host", "list_hosts"],
      sort: { id: "time", desc: true },
      page: 3,
      pageSize: 20,
    });
  });
});

describe("getMcpActivity scope", () => {
  test("a member sees only their own calls, whatever user filter the URL has", async () => {
    await getMcpActivity(
      viewer(false),
      mcpActivityFilters(state({ columnFilters: [{ id: "user", value: [OTHER] }] })),
    );
    const { sql, params } = calls[0];
    expect(sql).toContain("m.workspace_id = $1");
    expect(sql).toContain("($2::uuid IS NULL OR m.user_id = $2)");
    expect(params.slice(0, 2)).toEqual([WORKSPACE, ME]);
    // The filter still applies on top, so another user's id gives nothing.
    expect(params[3]).toEqual([OTHER]);
  });

  test("an administrator sees the workspace's calls", async () => {
    await getMcpActivity(viewer(true), mcpActivityFilters(state()));
    expect(calls[0].params.slice(0, 2)).toEqual([WORKSPACE, null]);
  });

  test("page and size become LIMIT and OFFSET", async () => {
    await getMcpActivity(
      viewer(true),
      mcpActivityFilters(state({ pagination: { pageIndex: 1, pageSize: 20 } })),
    );
    expect(calls[0].params.slice(-2)).toEqual([20, 20]);
  });
});

describe("getMcpActivityFacets scope", () => {
  test("a member: no user facet; clients and tools from their own calls", async () => {
    const facets = await getMcpActivityFacets(viewer(false));
    expect(facets.users).toEqual([]);
    expect(calls).toHaveLength(2);
    for (const c of calls) expect(c.params).toEqual([WORKSPACE, ME]);
  });

  test("an administrator: all three facets over the workspace", async () => {
    await getMcpActivityFacets(viewer(true));
    expect(calls).toHaveLength(3);
    for (const c of calls) expect(c.params).toEqual([WORKSPACE, null]);
  });
});
