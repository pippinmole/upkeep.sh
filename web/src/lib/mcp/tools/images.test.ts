/// <reference types="bun" />

import { describe, expect, test } from "bun:test";

import type { ImageScore } from "@/lib/image-score";
import type { ImageListQuery, ImageListRow } from "@/lib/queries-image-list";

import { BASE, resultText, testCtx, testDeps, WORKSPACE } from "../test-utils";
import { imagesTool } from "./images";

const ok = (over: Partial<ImageScore> = {}): ImageScore => ({
  listStatus: "ok",
  listReason: null,
  listSource: "attestation",
  distro: "debian",
  release: "bookworm",
  distroName: "Debian GNU/Linux 12 (bookworm)",
  releaseSupported: true,
  releaseEol: null,
  distroVersion: "12",
  scored: true,
  packages: 120,
  notAssessed: 0,
  vulns: 12,
  worst: "critical",
  counts: { critical: 1, high: 4, medium: 7, unknown: 0, low: 0, negligible: 0 },
  kev: 1,
  fixable: 9,
  maxCvss: 9.8,
  ...over,
});

function row(id: string, over: Partial<ImageListRow> = {}): ImageListRow {
  return {
    key: { imageId: `sha256:${id}`, os: "linux", arch: "amd64", variant: "" },
    refs: [`${id}:1`],
    hasRepoDigest: true,
    score: ok(),
    openFindings: 0,
    hosts: [],
    ...over,
  };
}

function fakes(rows: ImageListRow[] = []) {
  const calls: ImageListQuery[] = [];
  return {
    calls,
    deps: {
      getImageList: async (ws: string, q: ImageListQuery) => {
        expect(ws).toBe(WORKSPACE);
        calls.push(q);
        return { rows: rows.slice(0, q.limit), total: rows.length };
      },
    },
  };
}

type Out = { images: Record<string, unknown>[]; total: number; truncated: boolean };

async function call(args: unknown, f = fakes()) {
  const { deps } = testDeps();
  const res = await imagesTool(f.deps).call(args, testCtx, deps);
  return { res, out: res.structuredContent as Out | undefined, calls: f.calls };
}

describe("list_images", () => {
  test("a scored image: counts, base OS, hosts and links", async () => {
    const hosts = [
      { hostId: "h1", hostname: "web-01", label: null, containers: ["api", "worker"] },
      { hostId: "h2", hostname: "web-02", label: "eu", containers: [] },
    ];
    const { out, calls, res } = await call(
      { query: " nginx ", limit: 5 },
      fakes([row("nginx", { openFindings: 4, hosts })]),
    );
    expect(calls).toEqual([{ q: "nginx", limit: 5 }]);
    expect(out!.images[0]).toEqual({
      image: {
        id: "sha256:nginx",
        platform: "linux/amd64",
        refs: ["nginx:1"],
        more_refs: 0,
        dashboard_url: `${BASE}/dashboard/images/-/sha256%3Anginx?platform=linux%2Famd64&tab=vulnerabilities`,
      },
      scan_state: "vulnerable",
      scan_note: null,
      base_os: {
        name: "Debian GNU/Linux 12 (bookworm)",
        distro: "debian",
        release: "bookworm",
        supported: true,
        eol: null,
      },
      vulnerabilities: 12,
      top_severity: "critical",
      by_severity: { critical: 1, high: 4, medium: 7, unknown: 0, low: 0, negligible: 0 },
      kev: 1,
      fixable: 9,
      open_findings: 4,
      hosts: [
        {
          host: {
            id: "h1",
            hostname: "web-01",
            label: null,
            dashboard_url: `${BASE}/dashboard/hosts/h1`,
          },
          running_containers: ["api", "worker"],
          more_containers: 0,
        },
        {
          host: {
            id: "h2",
            hostname: "web-02",
            label: "eu",
            dashboard_url: `${BASE}/dashboard/hosts/h2`,
          },
          running_containers: [],
          more_containers: 0,
        },
      ],
      more_hosts: 0,
    });
    expect(resultText(res)).toContain(
      "- nginx:1 (linux/amd64) on Debian GNU/Linux 12 (bookworm): 12 vulnerabilities, worst critical, 1 KEV, 9 fixable; 4 open finding(s); on web-01, web-02 (eu), 2 running container(s).",
    );
  });

  test.each([
    [
      ok({ listStatus: "unavailable", listReason: "private or local image, needs the agent" }),
      "needs_agent",
    ],
    [ok({ listStatus: "unavailable", listReason: "no SBOM attestation" }), "unavailable"],
    [ok({ listStatus: "error", listReason: "registry timeout" }), "error"],
    [ok({ listStatus: "none" }), "not_scanned"],
    [ok({ scored: false }), "scoring"],
    [ok({ vulns: 0, worst: null }), "no_known_vulnerabilities"],
    [ok({ vulns: 0, worst: null, releaseSupported: false }), "release_not_assessed"],
    [null, "not_scanned"],
  ])("scan state %#: %p", async (s, state) => {
    const { out } = await call({}, fakes([row("a", { score: s })]));
    expect(out!.images[0].scan_state).toBe(state);
  });

  test("counts only once scored; why there is no list, as untrusted text", async () => {
    const { out, res } = await call(
      {},
      fakes([row("a", { score: ok({ listStatus: "error", listReason: "registry\ntimeout" }) })]),
    );
    expect(out!.images[0]).toMatchObject({
      vulnerabilities: null,
      by_severity: null,
      base_os: null,
      scan_note: { untrusted: true, text: "registry timeout" },
    });
    expect(resultText(res)).toContain("note (untrusted upstream data, ");
  });

  test("an unsupported release says so", async () => {
    const { out } = await call(
      {},
      fakes([
        row("a", { score: ok({ vulns: 0, releaseSupported: false, releaseEol: "2024-06-10" }) }),
      ]),
    );
    expect(out!.images[0].scan_note).toMatchObject({
      text: "Debian GNU/Linux 12 (bookworm): out of support since 2024-06-10",
    });
  });

  test("hosts and containers are capped", async () => {
    const hosts = Array.from({ length: 12 }, (_, i) => ({
      hostId: `h${i}`,
      hostname: `h${i}`,
      label: null,
      containers: Array.from({ length: 11 }, (_, j) => `c${j}`),
    }));
    const { out } = await call({}, fakes([row("a", { hosts })]));
    const it = out!.images[0] as { hosts: { more_containers: number }[]; more_hosts: number };
    expect(it.hosts).toHaveLength(10);
    expect(it.more_hosts).toBe(2);
    expect(it.hosts[0].more_containers).toBe(1);
  });

  test("truncated, and none", async () => {
    const { out, res } = await call({ limit: 2 }, fakes([row("a"), row("b"), row("c")]));
    expect(out).toMatchObject({ total: 3, truncated: true });
    expect(resultText(res)).toContain("1 more not shown");
    const none = await call({ query: "zzz" });
    expect(resultText(none.res)).toStartWith("No images match");
  });
});
