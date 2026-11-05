/// <reference types="bun" />

import { beforeEach, expect, mock, test } from "bun:test";

// getTopBarData against a fake pool: checks the binding and the row mapping.

let calls: { sql: string; params: unknown[] }[];
let rows: Record<string, unknown>[];
const query = mock(async (sql: string, params: unknown[] = []) => {
  calls.push({ sql, params });
  return { rows };
});
mock.module("./db", () => ({ pool: { query } }));

const { getTopBarData } = await import("./queries-nav");

const WS = "22222222-2222-4222-8222-222222222222";

beforeEach(() => {
  calls = [];
  rows = [];
});

test("binds the workspace and maps the row", async () => {
  rows = [{ workspace_name: "Acme", firing_alerts: "3", has_swarm: true }];
  expect(await getTopBarData(WS)).toEqual({ workspaceName: "Acme", firingAlerts: 3, hasSwarm: true });
  expect(calls[0].params).toEqual([WS]);
  expect(calls[0].sql).toContain("FROM workspaces");
});

test("missing row falls back to zeros and an empty name", async () => {
  rows = [];
  expect(await getTopBarData(WS)).toEqual({ workspaceName: "", firingAlerts: 0, hasSwarm: false });
});
