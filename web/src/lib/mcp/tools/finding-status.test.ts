/// <reference types="bun" />

import { describe, expect, test } from "bun:test";

import type { ImageKey } from "@/lib/image-key";
import type {
  FindingStatus,
  FindingStatusQuery,
  FindingStatusRow,
  ImageFindingStatus,
  ImageFindingStatusRow,
} from "@/lib/queries-finding-status";

import {
  BASE,
  expectHostErrors,
  expectImageErrors,
  fakeResolveHost,
  fakeResolveImage,
  HOST,
  IMAGE,
  resultText,
  testCtx,
  testDeps,
  WORKSPACE,
} from "../test-utils";
import { findingStatusTool } from "./finding-status";

function row(vulnKey: string, over: Partial<FindingStatusRow> = {}): FindingStatusRow {
  return {
    vulnKey,
    sourcePackage: "openssl",
    packages: ["libssl3"],
    status: "open",
    installedVersion: "3.0.13-0ubuntu3.1",
    fixedVersion: "3.0.13-0ubuntu3.4",
    fixChannel: "standard",
    severity: "high",
    isKev: false,
    firstSeenAt: "2026-10-01T00:00:00.000Z",
    resolvedAt: null,
    reopenedAt: null,
    ...over,
  };
}

const freshness = {
  snapshotCollectedAt: "2026-10-04T10:00:00.000Z",
  snapshotReceivedAt: "2026-10-04T10:00:01.000Z",
  pushIntervalSeconds: 900,
};

const SCANNED = {
  listStatus: "ok",
  listGeneratedAt: "2026-10-04T09:00:00.000Z",
  scored: true,
  scoredAt: "2026-10-04T09:05:00.000Z",
};

function fakes(status: Partial<FindingStatus> = {}, image: Partial<ImageFindingStatus> = {}) {
  const calls: [string, FindingStatusQuery][] = [];
  const imageCalls: [ImageKey, FindingStatusQuery][] = [];
  return {
    calls,
    imageCalls,
    deps: {
      resolveHost: fakeResolveHost,
      resolveImage: fakeResolveImage,
      getImageFindingStatus: async (ws: string, key: ImageKey, q: FindingStatusQuery) => {
        expect(ws).toBe(WORKSPACE);
        imageCalls.push([key, q]);
        const rows = image.rows ?? [];
        return {
          rows: rows.slice(0, q.limit),
          total: rows.length,
          unfixed: rows.filter((r) => r.fixedVersion === null).length,
          installed: image.installed ?? [],
          scan: image.scan ?? SCANNED,
        };
      },
      getFindingStatus: async (ws: string, hostId: string, q: FindingStatusQuery) => {
        expect(ws).toBe(WORKSPACE);
        calls.push([hostId, q]);
        const findings = status.findings ?? [];
        return {
          findings: findings.slice(0, q.limit),
          total: findings.length,
          open: findings.filter((f) => f.status === "open").length,
          openUnfixed: findings.filter((f) => f.status === "open" && f.fixedVersion === null)
            .length,
          installed: status.installed ?? [],
          freshness,
        };
      },
    },
  };
}

type Out = Record<string, unknown> & {
  findings: Record<string, unknown>[];
  image_vulnerabilities: Record<string, unknown>[];
};

async function call(args: unknown, f = fakes()) {
  const { deps, logged } = testDeps();
  const res = await findingStatusTool(f.deps).call(args, testCtx, deps);
  return {
    res,
    out: res.structuredContent as Out | undefined,
    logged,
    calls: f.calls,
    imageCalls: f.imageCalls,
  };
}

describe("get_finding_status arguments", () => {
  test("package or vulnerability is required", async () => {
    const { res, calls } = await call({ host: "web-01" });
    expect(res.isError).toBe(true);
    expect(resultText(res)).toBe("Invalid arguments: package: pass package, vulnerability or both");
    expect(calls).toHaveLength(0);
  });

  test("both reach the query", async () => {
    const { calls } = await call({
      host: "web-01",
      package: "openssl",
      vulnerability: "cve-2024-1",
    });
    expect(calls).toEqual([[HOST.id, { package: "openssl", vulnKey: "cve-2024-1", limit: 15 }]]);
  });

  test.each([
    [{ package: "openssl" }, "host"],
    [{ host: "web-01", image: "nginx:1.27", package: "openssl" }, "host"],
    [{ image: "nginx:1.27", platform: "", package: "openssl" }, "platform"],
    [{ host: "web-01", package: "" }, "package"],
    [{ host: "web-01", vulnerability: "x".repeat(101) }, "vulnerability"],
    [{ host: "web-01", package: "openssl", limit: 101 }, "limit"],
  ])("rejects %p", async (args, field) => {
    const { res } = await call(args);
    expect(res.isError).toBe(true);
    expect(resultText(res)).toStartWith(`Invalid arguments: ${field}:`);
  });

  test("unknown and ambiguous hosts are tool errors", async () => {
    await expectHostErrors(async (host) => (await call({ host, package: "openssl" })).res);
  });
});

describe("get_finding_status results", () => {
  test.each([
    [[], "no_findings"],
    [[row("A"), row("B")], "open"],
    [
      [row("A"), row("B", { status: "resolved", resolvedAt: "2026-10-04T10:00:30.000Z" })],
      "partly_resolved",
    ],
    [[row("A", { status: "resolved", resolvedAt: "2026-10-04T10:00:30.000Z" })], "resolved"],
  ] as const)("%p: %s", async (findings, status) => {
    const { out } = await call(
      { host: "web-01", package: "openssl" },
      fakes({ findings: [...findings] }),
    );
    expect(out!.status).toBe(status);
  });

  test("resolved findings carry when, and link to the resolved tab", async () => {
    const { out, res } = await call(
      { host: "web-01", vulnerability: "CVE-2024-1" },
      fakes({
        findings: [
          row("CVE-2024-1", { status: "resolved", resolvedAt: "2026-10-04T10:00:30.000Z" }),
        ],
      }),
    );
    expect(out).toMatchObject({
      status: "resolved",
      open: 0,
      resolved: 1,
      latest_snapshot: {
        collected_at: "2026-10-04T10:00:00.000Z",
        received_at: "2026-10-04T10:00:01.000Z",
      },
      push_interval_seconds: 900,
      next_snapshot_expected_by: "2026-10-04T10:15:00.000Z",
      awaiting_rematch: false,
      dashboard_url: `${BASE}/dashboard/hosts/${HOST.id}/vulnerabilities?kind=package&q=CVE-2024-1`,
    });
    expect(out!.findings[0]).toMatchObject({
      status: "resolved",
      resolved_at: "2026-10-04T10:00:30.000Z",
      dashboard_url: `${BASE}/dashboard/hosts/${HOST.id}/vulnerabilities?status=resolved&v=CVE-2024-1`,
    });
    expect(resultText(res)).toContain(
      "CVE-2024-1 on web-01: resolved (1 finding(s)), as of the snapshot collected at 2026-10-04T10:00:00.000Z.",
    );
  });

  test("still open after an upgrade the agent already reported: awaiting re-match", async () => {
    const installed = [
      {
        name: "libssl3",
        version: "3.0.13-0ubuntu3.4",
        arch: "amd64",
        sourceName: "openssl",
        sourceVersion: "3.0.13-0ubuntu3.4",
        since: "2026-10-04T09:59:00.000Z",
      },
    ];
    const upgraded = await call(
      { host: "web-01", package: "openssl" },
      fakes({ findings: [row("CVE-2024-1")], installed }),
    );
    expect(upgraded.out).toMatchObject({ status: "open", awaiting_rematch: true });
    expect(upgraded.out!.installed_now).toEqual([
      {
        package: "libssl3",
        version: "3.0.13-0ubuntu3.4",
        arch: "amd64",
        source_package: "openssl",
        source_version: "3.0.13-0ubuntu3.4",
        installed_since: "2026-10-04T09:59:00.000Z",
      },
    ]);
    expect(resultText(upgraded.res)).toContain("they update once the server re-matches");

    // Not upgraded yet (or not re-scanned): wait for the next snapshot.
    const old = await call(
      { host: "web-01", package: "openssl" },
      fakes({
        findings: [row("CVE-2024-1")],
        installed: [
          { ...installed[0], version: "3.0.13-0ubuntu3.1", sourceVersion: "3.0.13-0ubuntu3.1" },
        ],
      }),
    );
    expect(old.out!.awaiting_rematch).toBe(false);
    expect(resultText(old.res)).toContain(
      "wait for the next snapshot (expected by 2026-10-04T10:15:00.000Z)",
    );
  });

  test("open findings without a fix are told apart from ones waiting for a snapshot", async () => {
    const onlyUnfixed = await call(
      { host: "web-01", package: "glibc" },
      fakes({
        findings: [
          row("CVE-2026-1", { fixedVersion: null, fixChannel: null }),
          row("CVE-2024-2", { status: "resolved", resolvedAt: "2026-10-04T10:00:30.000Z" }),
        ],
      }),
    );
    expect(onlyUnfixed.out).toMatchObject({ status: "partly_resolved", open_without_fix: 1 });
    const text = resultText(onlyUnfixed.res);
    expect(text).toContain("1 open finding(s) have no fix published yet");
    expect(text).not.toContain("wait for the next snapshot");
  });

  test("truncated", async () => {
    const findings = Array.from({ length: 5 }, (_, i) => row(`CVE-2024-${i}`));
    const { out, logged } = await call(
      { host: "web-01", package: "linux", limit: 2 },
      fakes({ findings }),
    );
    expect(out!.findings).toHaveLength(2);
    expect(out).toMatchObject({ truncated: true, open: 5 });
    expect(logged[0].resultItems).toBe(2);
  });
});

function imageRow(
  vulnKey: string,
  over: Partial<ImageFindingStatusRow> = {},
): ImageFindingStatusRow {
  return {
    vulnKey,
    sourcePackage: "openssl",
    packages: ["libssl3"],
    ecosystem: "deb",
    installedVersion: "3.0.11-1~deb12u2",
    fixedVersion: "3.0.15-1~deb12u1",
    fixChannel: "standard",
    severity: "high",
    isKev: false,
    findings: [],
    ...over,
  };
}

describe("get_finding_status for an image", () => {
  test("the image and the filters reach the query; present means open", async () => {
    const rows = [
      imageRow("CVE-2024-1", {
        findings: [
          {
            hostId: HOST.id,
            hostname: HOST.hostname,
            label: null,
            status: "open",
            firstSeenAt: "2026-10-01T00:00:00.000Z",
            resolvedAt: null,
          },
        ],
      }),
      imageRow("CVE-2024-2", { fixedVersion: null, fixChannel: null }),
    ];
    const { out, res, imageCalls, calls } = await call(
      { image: "nginx:1.27", package: "OpenSSL" },
      fakes(
        {},
        {
          rows,
          installed: [
            { name: "libssl3", version: "3.0.11-1~deb12u2", ecosystem: "deb", paths: [] },
          ],
        },
      ),
    );
    expect(calls).toHaveLength(0);
    expect(imageCalls).toEqual([[IMAGE.key, { package: "OpenSSL", vulnKey: null, limit: 15 }]]);
    expect(out).toMatchObject({
      host: null,
      image: { id: IMAGE.key.imageId, platform: "linux/amd64" },
      status: "open",
      open: 2,
      open_without_fix: 1,
      findings: [],
      latest_snapshot: null,
      latest_scan: {
        list_status: "ok",
        list_generated_at: "2026-10-04T09:00:00.000Z",
        scored: true,
        scored_at: "2026-10-04T09:05:00.000Z",
      },
      installed_now: [{ package: "libssl3", version: "3.0.11-1~deb12u2", arch: null }],
    });
    expect(out!.image_vulnerabilities[0]).toMatchObject({
      id: "CVE-2024-1",
      origin: "os",
      fix: "standard",
      hosts: [{ host: { hostname: "web-01" }, status: "open" }],
    });
    const text = resultText(res);
    expect(text).toContain(
      "OpenSSL in nginx:1.27 (linux/amd64): present (2 vulnerability(ies)), as of the scan matched at 2026-10-04T09:05:00.000Z.",
    );
    expect(text).toContain("open on 1 of 1 host(s) running it");
    expect(text).toContain("ask again by tag");
  });

  test("a scanned image without it: no_findings", async () => {
    const { out, res } = await call({ image: "nginx:1.27", vulnerability: "CVE-2024-1" });
    expect(out!.status).toBe("no_findings");
    expect(resultText(res)).toContain("CVE-2024-1 in nginx:1.27 (linux/amd64): not present");
  });

  test("an image whose scan isn't current: not_scanned, whatever the rows", async () => {
    const { out, res } = await call(
      { image: "nginx:1.27", package: "openssl" },
      fakes(
        {},
        { scan: { listStatus: "ok", listGeneratedAt: null, scored: false, scoredAt: null } },
      ),
    );
    expect(out!.status).toBe("not_scanned");
    expect(resultText(res)).toContain("no current scan (package list ok, being matched)");
  });

  test("unknown and ambiguous images are tool errors", async () => {
    await expectImageErrors(async (image) => (await call({ image, package: "openssl" })).res);
  });
});
