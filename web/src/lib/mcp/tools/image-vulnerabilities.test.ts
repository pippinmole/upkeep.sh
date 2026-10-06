/// <reference types="bun" />

import { describe, expect, test } from "bun:test";

import type { ImageKey } from "@/lib/image-key";
import type { ImageScore } from "@/lib/image-score";
import type { ImageOverview } from "@/lib/queries-image";
import type { ImageEcosystemCount } from "@/lib/queries-image-list";
import type { ImageVulnFilters, ImageVulnRow } from "@/lib/queries-image-vulns";

import {
  BASE,
  expectImageErrors,
  fakeResolveImage,
  IMAGE,
  resultText,
  testCtx,
  testDeps,
  WORKSPACE,
} from "../test-utils";
import { imageVulnerabilitiesTool } from "./image-vulnerabilities";

const PAGE = `${BASE}/dashboard/images/-/${encodeURIComponent(IMAGE.key.imageId)}`;

function vuln(vulnKey: string, over: Partial<ImageVulnRow> = {}): ImageVulnRow {
  return {
    vulnKey,
    sourcePackage: "openssl",
    packages: ["libssl3"],
    ecosystem: "apk",
    paths: ["/lib/apk/db/installed"],
    installedVersion: "3.3.1-r0",
    fixedVersion: "3.3.2-r0",
    fixChannel: "standard",
    fixAdvisoryId: null,
    advisoryIds: [],
    distroSeverity: null,
    severity: "high",
    isKev: false,
    epssScore: 0.01,
    cvssV3Score: 7.5,
    description: "A flaw in openssl.",
    findings: [],
    ...over,
  };
}

function score(over: Partial<ImageScore> = {}): ImageScore {
  return {
    listStatus: "ok",
    listReason: null,
    listSource: "attestation",
    distro: "alpine",
    release: "3.20",
    distroName: "Alpine Linux v3.20",
    releaseSupported: true,
    releaseEol: "2026-04-01",
    distroVersion: "3.20.3",
    scored: true,
    packages: 40,
    notAssessed: 0,
    vulns: 3,
    worst: "high",
    counts: { critical: 0, high: 2, medium: 1, unknown: 0, low: 0, negligible: 0 },
    kev: 0,
    fixable: 3,
    maxCvss: 7.5,
    ...over,
  };
}

function overview(key: ImageKey, s: ImageScore | null): ImageOverview {
  return { key, tags: ["nginx:1.27"], digests: [], created: null, hosts: [], score: s, list: null };
}

function fakes(
  opts: {
    rows?: ImageVulnRow[];
    ecosystems?: ImageEcosystemCount[];
    score?: ImageScore | null;
    gone?: boolean;
  } = {},
) {
  const calls: ImageVulnFilters[] = [];
  const keys: ImageKey[] = [];
  const ecoCalls: unknown[] = [];
  const rows = opts.rows ?? [];
  return {
    calls,
    keys,
    ecoCalls,
    deps: {
      resolveImage: fakeResolveImage,
      getImageOverview: async (ws: string, key: ImageKey) => {
        expect(ws).toBe(WORKSPACE);
        return opts.gone ? null : overview(key, opts.score === undefined ? score() : opts.score);
      },
      getImageVulns: async (_ws: string, key: ImageKey, f: ImageVulnFilters) => {
        keys.push(key);
        calls.push(f);
        return { rows: rows.slice(0, f.pageSize), total: rows.length };
      },
      getImageVulnEcosystems: async (_ws: string, _key: ImageKey, f: unknown) => {
        ecoCalls.push(f);
        return opts.ecosystems ?? [];
      },
    },
  };
}

type Out = {
  vulnerabilities: Record<string, unknown>[];
  by_origin: Record<string, unknown>;
  [k: string]: unknown;
};

async function call(args: unknown, f = fakes()) {
  const { deps, logged } = testDeps();
  const res = await imageVulnerabilitiesTool(f.deps).call(args, testCtx, deps);
  return { res, out: res.structuredContent as Out | undefined, logged, f };
}

describe("get_image_vulnerabilities", () => {
  test("filters reach the queries in the tab's default order; the link carries them", async () => {
    const { f, out } = await call({
      image: IMAGE.key.imageId,
      min_severity: "high",
      kev_only: true,
      limit: 5,
    });
    expect(f.calls).toEqual([
      {
        q: null,
        severities: ["critical", "high"],
        kev: true,
        fix: null,
        sort: { id: "severity", desc: true },
        page: 1,
        pageSize: 5,
      },
    ]);
    expect(f.keys).toEqual([IMAGE.key]);
    expect(f.ecoCalls).toEqual([{ severities: ["critical", "high"], kev: true }]);
    expect(out!.dashboard_url).toBe(
      `${PAGE}?platform=linux%2Famd64&tab=vulnerabilities&severity=critical%2Chigh&kev=1`,
    );
  });

  test("layer attribution: each row's origin, and counts per origin", async () => {
    const rows = [
      vuln("CVE-2024-0001", { isKev: true }),
      vuln("CVE-2024-0002", {
        sourcePackage: "express",
        packages: ["express"],
        ecosystem: "npm",
        paths: ["/app/node_modules/express/package.json", "/a", "/b", "/c"],
        installedVersion: "4.17.1",
        fixedVersion: null,
        fixChannel: null,
        severity: "medium",
      }),
    ];
    const ecosystems = [
      { ecosystem: "apk", vulns: 7, fixable: 6, kev: 1 },
      { ecosystem: "deb", vulns: 1, fixable: 1, kev: 0 },
      { ecosystem: "npm", vulns: 2, fixable: 0, kev: 0 },
    ];
    const { out, res, logged } = await call({ image: "nginx:1.27" }, fakes({ rows, ecosystems }));
    expect(out!.by_origin).toEqual({
      os: { vulnerabilities: 8, fixable: 7, kev: 1 },
      application: { vulnerabilities: 2, fixable: 0, kev: 0 },
    });
    expect(out!.vulnerabilities[0]).toMatchObject({
      id: "CVE-2024-0001",
      package: "openssl",
      ecosystem: "apk",
      origin: "os",
      fix: "standard",
      kev: true,
      description: { untrusted: true, text: "A flaw in openssl." },
      dashboard_url: `${PAGE}?platform=linux%2Famd64&tab=vulnerabilities&q=CVE-2024-0001`,
    });
    expect(out!.vulnerabilities[1]).toMatchObject({
      origin: "application",
      ecosystem: "npm",
      paths: ["/app/node_modules/express/package.json", "/a", "/b"],
      more_paths: 1,
      fixed_version: null,
      fix: "none",
    });
    expect(out!.base_os).toEqual({
      name: "Alpine Linux v3.20",
      supported: true,
      eol: "2026-04-01",
    });
    expect(logged[0].resultItems).toBe(2);
    const text = resultText(res);
    expect(text).toContain(
      "By origin: 8 from OS packages (7 fixable, 1 KEV); 2 from application packages (0 fixable).",
    );
    expect(text).toContain("a newer base image tag in FROM");
    expect(text).toContain(
      "- CVE-2024-0002 [medium] express 4.17.1 -> no fix yet (application, npm at /app/node_modules/express/package.json, /a, /b +1).",
    );
    expect(text).toContain("description (untrusted upstream data");
  });

  test("mostly application packages: no FROM advice", async () => {
    const ecosystems = [
      { ecosystem: "apk", vulns: 1, fixable: 1, kev: 0 },
      { ecosystem: "pypi", vulns: 4, fixable: 4, kev: 0 },
    ];
    const rows = [vuln("CVE-1", { ecosystem: "pypi" })];
    const { res } = await call({ image: "nginx:1.27" }, fakes({ rows, ecosystems }));
    expect(resultText(res)).not.toContain("FROM");
  });

  test("open findings on hosts are counted per row", async () => {
    const f = (status: "open" | "resolved") => ({
      hostId: "h",
      hostname: "web-01",
      label: null,
      status,
      firstSeenAt: "2026-10-01T00:00:00.000Z",
      resolvedAt: null,
      reopenedAt: null,
    });
    const rows = [vuln("CVE-1", { findings: [f("open"), f("open"), f("resolved")] })];
    const { out } = await call({ image: "nginx:1.27" }, fakes({ rows }));
    expect(out!.vulnerabilities[0].open_on_hosts).toBe(2);
  });

  test("an image without a list: its state and why, no rows", async () => {
    const { out, res } = await call(
      { image: "nginx:1.27" },
      fakes({
        score: score({
          listStatus: "unavailable",
          listReason: "private or local image, needs the agent",
          scored: false,
          vulns: null,
        }),
      }),
    );
    expect(out).toMatchObject({ scan_state: "needs_agent", total: 0, base_os: null });
    expect(out!.scan_note).toMatchObject({ text: "private or local image, needs the agent" });
    expect(resultText(res)).toContain("no vulnerabilities to list (scan state: needs_agent)");
  });

  test("truncated", async () => {
    const rows = Array.from({ length: 4 }, (_, i) => vuln(`CVE-${i}`));
    const { out, res } = await call({ image: "nginx:1.27", limit: 3 }, fakes({ rows }));
    expect(out).toMatchObject({ total: 4, truncated: true });
    expect(resultText(res)).toContain("1 more not shown");
  });

  test("an image gone between the lookup and the read", async () => {
    const { res } = await call({ image: "nginx:1.27" }, fakes({ gone: true }));
    expect(res.isError).toBe(true);
    expect(resultText(res)).toContain("no longer on any host");
  });

  test("unknown and ambiguous images", async () => {
    await expectImageErrors((image) => call({ image }).then((r) => r.res));
  });

  test("platform picks between an id's platforms", async () => {
    const { res, f } = await call({ image: "multi", platform: "linux/arm64/v8" });
    expect(res.isError).toBeFalsy();
    expect(f.keys).toEqual([{ imageId: "sha256:cccc", os: "linux", arch: "arm64", variant: "v8" }]);
  });
});
