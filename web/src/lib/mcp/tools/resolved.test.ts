/// <reference types="bun" />

import { describe, expect, test } from "bun:test";

import type { ResolvedFindingRow, ResolvedQuery } from "@/lib/queries-finding-status";

import {
  BASE,
  expectHostErrors,
  fakeResolveHost,
  HOST,
  resultText,
  testCtx,
  testDeps,
  WORKSPACE,
} from "../test-utils";
import { resolvedTool } from "./resolved";

const NOW = Date.parse("2026-10-04T12:00:00.000Z");

function row(vulnKey: string, over: Partial<ResolvedFindingRow> = {}): ResolvedFindingRow {
  return {
    kind: "package",
    hostId: HOST.id,
    hostname: "web-01",
    label: null,
    vulnKey,
    sourcePackage: "openssl",
    packages: ["libssl3"],
    installedVersion: "3.0.13-0ubuntu3.1",
    fixedVersion: "3.0.13-0ubuntu3.4",
    severity: "high",
    isKev: false,
    firstSeenAt: "2026-10-01T00:00:00.000Z",
    resolvedAt: "2026-10-04T10:00:30.000Z",
    image: null,
    ...over,
  };
}

function fakes(rows: ResolvedFindingRow[] = []) {
  const calls: ResolvedQuery[] = [];
  return {
    calls,
    deps: {
      resolveHost: fakeResolveHost,
      now: () => NOW,
      getResolvedFindings: async (ws: string, q: ResolvedQuery) => {
        expect(ws).toBe(WORKSPACE);
        calls.push(q);
        return { rows: rows.slice(0, q.limit), total: rows.length };
      },
    },
  };
}

type Out = {
  since: string;
  items: Record<string, unknown>[];
  total: number;
  truncated: boolean;
  dashboard_url: string;
  host: { id: string } | null;
};

async function call(args: unknown, f = fakes()) {
  const { deps, logged } = testDeps();
  const res = await resolvedTool(f.deps).call(args, testCtx, deps);
  return { res, out: res.structuredContent as Out | undefined, logged, calls: f.calls };
}

describe("list_resolved arguments", () => {
  test("defaults: the last 7 days, the whole fleet, limit 15", async () => {
    const { calls, out } = await call(undefined);
    expect(calls).toEqual([{ since: "2026-09-27T12:00:00.000Z", hostId: null, limit: 15 }]);
    expect(out).toMatchObject({
      since: "2026-09-27T12:00:00.000Z",
      host: null,
      dashboard_url: `${BASE}/dashboard/vulnerabilities?status=resolved`,
    });
  });

  test("since as a date or a date-time with an offset; host by name", async () => {
    expect((await call({ since: "2026-10-01" })).calls[0].since).toBe("2026-10-01T00:00:00.000Z");
    const { calls, out } = await call({ since: "2026-10-01T12:00:00+02:00", host: "web-01" });
    expect(calls[0]).toEqual({ since: "2026-10-01T10:00:00.000Z", hostId: HOST.id, limit: 15 });
    expect(out!.dashboard_url).toBe(
      `${BASE}/dashboard/hosts/${HOST.id}/vulnerabilities?status=resolved`,
    );
  });

  test.each([
    [{ since: "yesterday" }, "since"],
    [{ since: "2026-13-01" }, "since"],
    [{ since: 1 }, "since"],
    [{ host: "" }, "host"],
    [{ limit: 0 }, "limit"],
  ])("rejects %p", async (args, field) => {
    const { res, calls } = await call(args);
    expect(res.isError).toBe(true);
    expect(resultText(res)).toStartWith(`Invalid arguments: ${field}:`);
    expect(calls).toHaveLength(0);
  });

  test("unknown and ambiguous hosts are tool errors", async () => {
    await expectHostErrors(async (host) => (await call({ host })).res);
  });
});

describe("list_resolved results", () => {
  test("host package and image findings, with links", async () => {
    const { out, res } = await call(
      {},
      fakes([
        row("CVE-2024-1", { isKev: true }),
        row("CVE-2023-4911", {
          kind: "image",
          sourcePackage: "glibc",
          image: {
            id: "sha256:abc",
            os: "linux",
            arch: "amd64",
            variant: "",
            refs: ["nginx:1.27"],
          },
        }),
      ]),
    );
    expect(out!.items[0]).toMatchObject({
      kind: "host",
      id: "CVE-2024-1",
      kev: true,
      image: null,
      host: { id: HOST.id, hostname: "web-01" },
      dashboard_url: `${BASE}/dashboard/hosts/${HOST.id}/vulnerabilities?status=resolved&v=CVE-2024-1`,
    });
    expect(out!.items[1]).toMatchObject({
      kind: "image",
      image: {
        id: "sha256:abc",
        platform: "linux/amd64",
        refs: ["nginx:1.27"],
        dashboard_url: `${BASE}/dashboard/images/-/sha256%3Aabc?platform=linux%2Famd64&tab=vulnerabilities`,
      },
      dashboard_url: `${BASE}/dashboard/hosts/${HOST.id}/vulnerabilities?status=resolved&v=CVE-2023-4911&kind=image`,
    });
    expect(resultText(res)).toContain(
      "CVE-2023-4911 [high] glibc 3.0.13-0ubuntu3.1 on image nginx:1.27 on web-01",
    );
  });

  test("truncated", async () => {
    const rows = Array.from({ length: 5 }, (_, i) => row(`CVE-2024-${i}`));
    const { out, logged, res } = await call({ limit: 2 }, fakes(rows));
    expect(out).toMatchObject({ total: 5, truncated: true });
    expect(out!.items).toHaveLength(2);
    expect(logged[0].resultItems).toBe(2);
    expect(resultText(res)).toContain("3 more not shown");
  });

  test("nothing resolved", async () => {
    const { res } = await call({ host: "web-01" });
    expect(resultText(res)).toContain(
      "No findings resolved on web-01 since 2026-09-27T12:00:00.000Z",
    );
  });
});
