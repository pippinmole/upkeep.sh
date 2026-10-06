/// <reference types="bun" />

import { describe, expect, test } from "bun:test";

import type { HostListRow } from "@/lib/queries";
import type { EstateHealth, HostHealth } from "@/lib/queries-overview";

import { BASE, resultText, testCtx, testDeps, WORKSPACE } from "../test-utils";
import { hostsTool } from "./hosts";

function health(
  id: string,
  state: HostHealth["state"],
  over: Partial<HostHealth> = {},
): HostHealth {
  return {
    id,
    name: id,
    state,
    reported: true,
    stale: state === "stale",
    reboot: state === "reboot",
    kev: state === "kev" ? 1 : 0,
    critical: 0,
    ...over,
  };
}

function hostRow(id: string, over: Partial<HostListRow> = {}): HostListRow {
  return {
    id,
    hostname: id,
    label: null,
    osFamily: "debian",
    osId: "ubuntu",
    osVersion: "24.04",
    osCodename: "noble",
    kernel: "6.8.0-45-generic",
    duplicateOf: null,
    archivedAt: null,
    mergedInto: null,
    createdAt: "2026-09-01T00:00:00.000Z",
    lastSeenAt: "2026-10-04T10:00:00.000Z",
    agents: [
      {
        id: "a",
        name: "agent-1",
        mode: "local",
        status: "online",
        errorCode: null,
        keyPending: false,
        collected: true,
      },
    ],
    openFindings: 3,
    topSeverity: "high",
    openVulns: 3,
    kevVulns: 0,
    topVulnSeverity: "high",
    rebootRequired: false,
    firingAlerts: 0,
    ...over,
  };
}

// Estate health in name order (as getEstateHealth returns it).
const estate: EstateHealth = {
  hosts: [
    health("api-01", "ok"),
    health("db-01", "reboot"),
    health("web-01", "kev", { critical: 2 }),
    health("web-02", "ok"),
  ],
  signals: {
    containers: 0,
    images: 0,
    criticalImages: 0,
    failedDeliveries: 0,
    firingAlerts: 0,
    neverConnected: [],
  },
};

const rows = [
  hostRow("api-01"),
  hostRow("db-01", { label: "Primary DB" }),
  hostRow("web-01", { openVulns: 7, topVulnSeverity: "critical" }),
  hostRow("web-02"),
  // Archived: in getHosts, not in the estate.
  hostRow("old-01", { archivedAt: "2026-09-01T00:00:00.000Z" }),
];

type Out = {
  hosts: { id: string; [k: string]: unknown }[];
  total: number;
  truncated: boolean;
};

async function call(args: unknown) {
  const { deps, logged } = testDeps();
  const tool = hostsTool({
    getEstateHealth: async (ws) => {
      expect(ws).toBe(WORKSPACE);
      return estate;
    },
    getHosts: async (ws) => {
      expect(ws).toBe(WORKSPACE);
      return rows;
    },
  });
  const res = await tool.call(args, testCtx, deps);
  return { res, out: res.structuredContent as Out | undefined, logged };
}

describe("list_hosts", () => {
  test("worst state first, then by name; archived hosts left out", async () => {
    const { out, logged } = await call(undefined);
    expect(out!.hosts.map((h) => [h.id, h.state])).toEqual([
      ["web-01", "kev"],
      ["db-01", "reboot"],
      ["api-01", "ok"],
      ["web-02", "ok"],
    ]);
    expect(out).toMatchObject({ total: 4, truncated: false });
    expect(logged[0].arguments).toEqual({ limit: 15 });
  });

  test("a host's facts and links", async () => {
    const { out, res } = await call({ query: "WEB-01" });
    expect(out!.hosts).toEqual([
      {
        id: "web-01",
        hostname: "web-01",
        label: null,
        state: "kev",
        os: "Ubuntu 24.04 (noble)",
        kernel: "6.8.0-45-generic",
        reboot_pending: false,
        stale: false,
        open_vulnerabilities: 7,
        kev_findings: 1,
        critical_findings: 2,
        top_severity: "critical",
        last_seen_at: "2026-10-04T10:00:00.000Z",
        agents: [{ name: "agent-1", mode: "local", status: "online" }],
        dashboard_url: `${BASE}/dashboard/hosts/web-01`,
      },
    ]);
    expect(resultText(res)).toContain(
      "- web-01 [kev] Ubuntu 24.04 (noble): 7 open, 1 KEV, 2 critical",
    );
  });

  test("query matches the label too; state filters", async () => {
    expect((await call({ query: "primary" })).out!.hosts.map((h) => h.id)).toEqual(["db-01"]);
    expect((await call({ state: "ok" })).out!.hosts.map((h) => h.id)).toEqual(["api-01", "web-02"]);
    expect((await call({ query: "old" })).out).toMatchObject({ hosts: [], total: 0 });
  });

  test("truncated", async () => {
    const { out, res, logged } = await call({ limit: 2 });
    expect(out).toMatchObject({ total: 4, truncated: true });
    expect(out!.hosts).toHaveLength(2);
    expect(logged[0].resultItems).toBe(2);
    expect(resultText(res)).toContain("2 more not shown");
  });

  test.each([
    [{ limit: 0 }, "limit"],
    [{ limit: 101 }, "limit"],
    [{ state: "broken" }, "state"],
    [{ query: "" }, "query"],
    [{ query: 5 }, "query"],
  ])("rejects %p", async (args, field) => {
    const { res } = await call(args);
    expect(res.isError).toBe(true);
    expect(resultText(res)).toStartWith(`Invalid arguments: ${field}:`);
  });
});
