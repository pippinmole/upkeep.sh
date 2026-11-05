/// <reference types="bun" />

import { beforeEach, expect, mock, test } from "bun:test";

// getMachines against a fake pool: checks the binding, the SQL shape and the row mapping.

let calls: { sql: string; params: unknown[] }[];
let rows: Record<string, unknown>[];
const query = mock(async (sql: string, params: unknown[] = []) => {
  calls.push({ sql, params });
  return { rows };
});
mock.module("./db", () => ({ pool: { query } }));

const { getMachines } = await import("./queries-machines");

const WS = "22222222-2222-4222-8222-222222222222";

const fixtureRow = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  id: "h1",
  hostname: "web-1",
  label: null,
  os_id: "ubuntu",
  os_version: "24.04",
  public_ipv4: "203.0.113.5",
  public_ipv6: null,
  last_seen_at: new Date("2026-11-01T00:00:00Z"),
  archived_at: null,
  reported: true,
  agents: [{ id: "a1", name: "a1", mode: "local", status: "online" }],
  crit: "1",
  high: "2",
  med: "3",
  low: "4",
  kev: "1",
  img_vulns: "0",
  img_crit: "0",
  img_kev: "0",
  img_count: "0",
  duplicate_of: null,
  duplicate_of_hostname: null,
  duplicate_of_label: null,
  merged_into: null,
  merged_into_hostname: null,
  reboot_required: null,
  ...over,
});

beforeEach(() => {
  calls = [];
  rows = [];
});

test("scoped, sorted by hostname, host packages and running images apart", async () => {
  await getMachines(WS);
  expect(calls[0].params).toEqual([WS]);
  expect(calls[0].sql).toContain("WHERE h.workspace_id = $1");
  expect(calls[0].sql).toMatch(/ORDER BY lower\(h\.hostname\), h\.id/);
  expect(calls[0].sql).toContain("kind = 'vulnerable_package'");
  expect(calls[0].sql).toContain("kind = 'vulnerable_image'");
  expect(calls[0].sql).toContain("host_containers");
});

test("maps counts to numbers and nulls through", async () => {
  rows = [fixtureRow({ crit: "2", high: "0", img_vulns: "5", public_ipv4: null, public_ipv6: "2001:db8::1", agents: null })];
  const [m] = await getMachines(WS);
  expect(m.vulns).toEqual({ critical: 2, high: 0, medium: 3, low: 4, kev: 1 });
  expect(m.images.vulns).toBe(5);
  expect(m.ip).toBe("2001:db8::1");
  expect(m.agents).toEqual([]);
  expect(m.rebootRequired).toBe(false);
  expect(m.lastSeenAt).toBe("2026-11-01T00:00:00.000Z");
  expect(m.archivedAt).toBeNull();
});

test("maps duplicate and merged links", async () => {
  rows = [
    fixtureRow({
      duplicate_of: "h0",
      duplicate_of_hostname: "web-0",
      duplicate_of_label: "Prod",
      merged_into: "h9",
      merged_into_hostname: "web-9",
    }),
  ];
  const [m] = await getMachines(WS);
  expect(m.duplicateOf).toEqual({ id: "h0", hostname: "web-0", label: "Prod" });
  expect(m.mergedInto).toEqual({ id: "h9", hostname: "web-9" });
});
