/// <reference types="bun" />

import { describe, expect, test } from "bun:test";

import type {
  ImagePackageMatchRow,
  PackageInstallRow,
  PackageSearch,
} from "@/lib/queries-package-search";

import { BASE, IMAGE, resultText, testCtx, testDeps, WORKSPACE } from "../test-utils";
import { findPackageTool } from "./find-package";

function install(hostname: string, over: Partial<PackageInstallRow> = {}): PackageInstallRow {
  return {
    hostId: `id-${hostname}`,
    hostname,
    label: null,
    ecosystem: "deb",
    distro: "ubuntu",
    release: "noble",
    name: "libssl3",
    version: "3.0.13-0ubuntu3.1",
    arch: "amd64",
    sourceName: "openssl",
    sourceVersion: "3.0.13-0ubuntu3.1",
    since: "2026-09-01T00:00:00.000Z",
    openFindings: 0,
    kevFindings: 0,
    fixableFindings: 0,
    topSeverity: null,
    ...over,
  };
}

function imagePkg(over: Partial<ImagePackageMatchRow> = {}): ImagePackageMatchRow {
  return {
    key: IMAGE.key,
    refs: IMAGE.refs,
    ecosystem: "deb",
    distro: "debian",
    release: "bookworm",
    name: "libssl3",
    version: "3.0.11-1~deb12u2",
    arch: "amd64",
    sourceName: "openssl",
    sourceVersion: "3.0.11-1~deb12u2",
    paths: ["/var/lib/dpkg/status"],
    hosts: 2,
    vulns: 0,
    kevVulns: 0,
    fixableVulns: 0,
    topSeverity: null,
    ...over,
  };
}

function fakes(rows: PackageInstallRow[] = [], images: ImagePackageMatchRow[] = []) {
  const calls: PackageSearch[] = [];
  const imageCalls: PackageSearch[] = [];
  return {
    calls,
    imageCalls,
    deps: {
      findPackageInImages: async (ws: string, q: PackageSearch) => {
        expect(ws).toBe(WORKSPACE);
        imageCalls.push(q);
        return {
          rows: images.slice(0, q.limit),
          total: images.length,
          images: new Set(images.map((r) => r.key.imageId)).size,
        };
      },
      findPackageOnHosts: async (ws: string, q: PackageSearch) => {
        expect(ws).toBe(WORKSPACE);
        calls.push(q);
        return {
          rows: rows.slice(0, q.limit),
          total: rows.length,
          hosts: new Set(rows.map((r) => r.hostId)).size,
        };
      },
    },
  };
}

type Out = {
  matches: Record<string, unknown>[];
  hosts: number;
  total: number;
  truncated: boolean;
  dashboard_url: string;
};

async function call(args: unknown, f = fakes()) {
  const { deps, logged } = testDeps();
  const res = await findPackageTool(f.deps).call(args, testCtx, deps);
  return {
    res,
    out: res.structuredContent as Out | undefined,
    logged,
    calls: f.calls,
    imageCalls: f.imageCalls,
  };
}

describe("find_package", () => {
  test("arguments reach the query; installs map with links", async () => {
    const rows = [
      install("web-01", {
        openFindings: 3,
        kevFindings: 1,
        fixableFindings: 2,
        topSeverity: "high",
      }),
      install("web-02", { version: "3.0.13-0ubuntu3.4", sourceVersion: "3.0.13-0ubuntu3.4" }),
    ];
    const { out, calls, res } = await call({ name: " openssl ", version: "3.0.13" }, fakes(rows));
    expect(calls).toEqual([{ name: "openssl", version: "3.0.13", limit: 15 }]);
    expect(out).toMatchObject({ hosts: 2, total: 2, truncated: false });
    expect(out!.dashboard_url).toBe(`${BASE}/dashboard/packages/openssl`);
    expect(out!.matches[0]).toEqual({
      kind: "host",
      host: {
        id: "id-web-01",
        hostname: "web-01",
        label: null,
        dashboard_url: `${BASE}/dashboard/hosts/id-web-01`,
      },
      package: "libssl3",
      version: "3.0.13-0ubuntu3.1",
      arch: "amd64",
      source_package: "openssl",
      source_version: "3.0.13-0ubuntu3.1",
      ecosystem: "deb",
      distro: "ubuntu",
      release: "noble",
      installed_since: "2026-09-01T00:00:00.000Z",
      vulnerable: true,
      open_findings: 3,
      kev_findings: 1,
      fixable_findings: 2,
      top_severity: "high",
      dashboard_url: `${BASE}/dashboard/hosts/id-web-01/packages?q=libssl3`,
    });
    expect(out!.matches[1]).toMatchObject({ vulnerable: false, open_findings: 0 });
    const text = resultText(res);
    expect(text).toContain(
      "- host web-01: libssl3 3.0.13-0ubuntu3.1 amd64 (source openssl 3.0.13-0ubuntu3.1); vulnerable: 3 open finding(s), worst high, 1 KEV.",
    );
    expect(text).toContain("no open findings");
  });

  test("truncated", async () => {
    const rows = Array.from({ length: 4 }, (_, i) => install(`h${i}`));
    const { out, logged, res } = await call({ name: "libssl3", limit: 3 }, fakes(rows));
    expect(out).toMatchObject({ total: 4, truncated: true });
    expect(out!.matches).toHaveLength(3);
    expect(logged[0].resultItems).toBe(3);
    expect(resultText(res)).toContain("1 more not shown");
  });

  test("not installed anywhere", async () => {
    const { out, res } = await call({ name: "nginx" });
    expect(out).toMatchObject({ matches: [], total: 0, truncated: false });
    expect(resultText(res)).toContain("nginx is not installed on any host or in any image on them");
  });

  test("image packages: the image, origin, paths and whether vulnerable there", async () => {
    const images = [
      imagePkg({ vulns: 3, kevVulns: 1, fixableVulns: 2, topSeverity: "critical" }),
      imagePkg({
        ecosystem: "npm",
        distro: "",
        release: "",
        name: "openssl",
        version: "1.0.0",
        arch: "",
        sourceName: null,
        sourceVersion: null,
        paths: ["/app/node_modules/openssl/package.json", "/b", "/c", "/d"],
      }),
    ];
    const { out, res, calls, imageCalls } = await call({ name: "openssl" }, fakes([], images));
    expect(calls).toEqual([{ name: "openssl", version: null, limit: 15 }]);
    expect(imageCalls).toEqual(calls);
    expect(out).toMatchObject({ hosts: 0, images: 1, total: 2, truncated: false });
    expect(out!.matches[0]).toEqual({
      kind: "image",
      image: {
        id: IMAGE.key.imageId,
        platform: "linux/amd64",
        refs: IMAGE.refs,
        more_refs: 0,
        dashboard_url: `${BASE}/dashboard/images/-/${encodeURIComponent(IMAGE.key.imageId)}?platform=linux%2Famd64`,
      },
      package: "libssl3",
      version: "3.0.11-1~deb12u2",
      arch: "amd64",
      source_package: "openssl",
      source_version: "3.0.11-1~deb12u2",
      ecosystem: "deb",
      origin: "os",
      paths: ["/var/lib/dpkg/status"],
      more_paths: 0,
      hosts: 2,
      vulnerable: true,
      vulnerabilities: 3,
      kev_vulnerabilities: 1,
      fixable_vulnerabilities: 2,
      top_severity: "critical",
      dashboard_url: `${BASE}/dashboard/images/-/${encodeURIComponent(IMAGE.key.imageId)}?platform=linux%2Famd64&q=libssl3`,
    });
    expect(out!.matches[1]).toMatchObject({
      origin: "application",
      more_paths: 1,
      vulnerable: false,
    });
    const text = resultText(res);
    expect(text).toContain(
      "- image nginx:1.27 (linux/amd64): libssl3 3.0.11-1~deb12u2 (source openssl 3.0.11-1~deb12u2) [os, deb] at /var/lib/dpkg/status; vulnerable: 3 vulnerabilities, worst critical, 1 KEV; on 2 host(s).",
    );
    expect(text).toContain("no known vulnerabilities");
  });

  test("hosts first, then images; limit applies to each kind", async () => {
    const rows = Array.from({ length: 3 }, (_, i) => install(`h${i}`));
    const images = Array.from({ length: 3 }, () => imagePkg());
    const { out } = await call({ name: "libssl3", limit: 2 }, fakes(rows, images));
    expect(out!.matches.map((m) => m.kind)).toEqual(["host", "host", "image", "image"]);
    expect(out).toMatchObject({ total: 6, truncated: true });
  });

  test.each([
    ["host", 1, 0],
    ["image", 0, 1],
  ] as const)("kind %s queries only that kind", async (kind, hostCalls, imageCalls) => {
    const r = await call({ name: "libssl3", kind });
    expect(r.calls).toHaveLength(hostCalls);
    expect(r.imageCalls).toHaveLength(imageCalls);
  });

  test.each([
    [{}, "name"],
    [{ name: "" }, "name"],
    [{ name: "   " }, "name"],
    [{ name: "x".repeat(201) }, "name"],
    [{ name: "openssl", version: "" }, "version"],
    [{ name: "openssl", limit: 0 }, "limit"],
  ])("rejects %p", async (args, field) => {
    const { res, calls } = await call(args);
    expect(res.isError).toBe(true);
    expect(resultText(res)).toStartWith(`Invalid arguments: ${field}:`);
    expect(calls).toHaveLength(0);
  });
});
