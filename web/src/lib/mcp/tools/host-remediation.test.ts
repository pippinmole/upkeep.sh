/// <reference types="bun" />

import { describe, expect, test } from "bun:test";

import { parseHostVulnFilters, searchParamsOf } from "@/lib/host-vulns-filters";
import {
  groupRemediation,
  type RemediationFilters,
  type RemediationFinding,
} from "@/lib/queries-remediation";
import type { KernelPackage } from "@/lib/queries-vulns";

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
import { hostRemediationTool } from "./host-remediation";

function finding(vulnKey: string, src: string, over: Partial<RemediationFinding> = {}) {
  return {
    vulnKey,
    sourcePackage: src,
    packages: [src],
    installedVersion: "1.0-1",
    fixedVersion: "1.0-2",
    fixChannel: "standard",
    severity: "high",
    isKev: false,
    kernelRelease: null,
    ...over,
  } satisfies RemediationFinding;
}

const runningKernel: KernelPackage = {
  softwareId: "1",
  name: "linux-image-6.8.0-45-generic",
  version: "6.8.0-45.45",
  arch: "amd64",
  sourcePackage: "linux",
  kernelRelease: "6.8.0-45-generic",
  isRunning: true,
  firstSeenAt: "2026-10-01T00:00:00.000Z",
  vulnCount: 1,
  fixableCount: 1,
};

// The real grouping over fake findings, recording the filters queried.
function fakes(findings: RemediationFinding[] = [], kernels: KernelPackage[] = []) {
  const calls: [string, RemediationFilters][] = [];
  return {
    calls,
    deps: {
      resolveHost: fakeResolveHost,
      getHostRemediation: async (ws: string, hostId: string, f: RemediationFilters) => {
        expect(ws).toBe(WORKSPACE);
        calls.push([hostId, f]);
        const running = kernels.find((k) => k.isRunning)?.kernelRelease ?? null;
        return { ...groupRemediation(findings, kernels), runningKernel: running };
      },
    },
  };
}

type Pkg = { package: string; [k: string]: unknown };
type Out = {
  upgrades: Pkg[];
  no_fix: Pkg[];
  totals: { upgrades: number; no_fix: number; findings: number };
  truncated: boolean;
  reboot_after_upgrade: boolean;
  running_kernel: string | null;
  dashboard_url: string;
};

async function call(args: unknown, f = fakes()) {
  const { deps, logged } = testDeps();
  const res = await hostRemediationTool(f.deps).call(args, testCtx, deps);
  return { res, out: res.structuredContent as Out | undefined, logged, calls: f.calls };
}

const sample = [
  finding("CVE-2024-1", "openssl", {
    severity: "critical",
    isKev: true,
    packages: ["libssl3", "openssl"],
    installedVersion: "3.0.13-0ubuntu3.1",
    fixedVersion: "3.0.13-0ubuntu3.4",
  }),
  finding("CVE-2024-2", "linux", {
    packages: ["linux-image-6.8.0-45-generic"],
    installedVersion: "6.8.0-45.45",
    fixedVersion: "6.8.0-50.50",
    kernelRelease: "6.8.0-45-generic",
  }),
  finding("CVE-2024-3", "openssl", {
    installedVersion: "3.0.13-0ubuntu3.1",
    fixedVersion: "3.0.13-0ubuntu3.10",
  }),
  finding("CVE-2024-4", "openssl", { fixedVersion: null, fixChannel: null, severity: "medium" }),
  finding("CVE-2024-5", "libxml2", {
    installedVersion: "2.9.13+dfsg-1ubuntu0.3",
    fixedVersion: "2.9.13+dfsg-1ubuntu0.5+esm1",
    fixChannel: "ubuntu-pro",
  }),
  finding("CVE-2024-6", "vim", { fixedVersion: null, fixChannel: null, severity: "low" }),
];

describe("get_host_remediation arguments", () => {
  test("host is required; defaults: no severity filter, all findings, limit 15", async () => {
    const missing = await call({});
    expect(missing.res.isError).toBe(true);
    expect(resultText(missing.res)).toStartWith("Invalid arguments: host:");

    const { calls, logged, out } = await call({ host: "web-01" });
    expect(calls).toEqual([[HOST.id, { severities: null, kev: false }]]);
    expect(logged[0].arguments).toEqual({ host: "web-01", kev_only: false, limit: 15 });
    expect(out?.dashboard_url).toBe(
      `${BASE}/dashboard/hosts/${HOST.id}/vulnerabilities?kind=package`,
    );
  });

  test.each([
    [{ host: "" }, "host"],
    [{ host: "web-01", min_severity: "severe" }, "min_severity"],
    [{ host: "web-01", kev_only: 1 }, "kev_only"],
    [{ host: "web-01", limit: 0 }, "limit"],
    [{ host: "web-01", limit: 101 }, "limit"],
  ])("rejects %p", async (args, field) => {
    const { res, calls } = await call(args);
    expect(res.isError).toBe(true);
    expect(resultText(res)).toStartWith(`Invalid arguments: ${field}:`);
    expect(calls).toHaveLength(0);
  });

  test("unknown and ambiguous hosts are tool errors", async () => {
    await expectHostErrors(async (host) => (await call({ host })).res);
  });

  test("filters reach the query and the dashboard_url parses to the same ones", async () => {
    const { calls, out } = await call({ host: HOST.id, min_severity: "high", kev_only: true });
    expect(calls[0][1]).toEqual({ severities: ["critical", "high"], kev: true });
    const u = new URL(out!.dashboard_url);
    const { filters } = parseHostVulnFilters(searchParamsOf(u.searchParams));
    expect(filters).toMatchObject({
      status: "open",
      kinds: ["package"],
      severities: ["critical", "high"],
      kev: true,
    });
  });
});

describe("get_host_remediation results", () => {
  test("one entry per package: highest fix, CVEs cleared, kernel, Pro, unfixed apart", async () => {
    const { out, res } = await call({ host: "web-01" }, fakes(sample, [runningKernel]));
    expect(out!.upgrades.map((p) => p.package)).toEqual(["openssl", "linux", "libxml2"]);
    expect(out!.no_fix.map((p) => p.package)).toEqual(["vim"]);
    expect(out!.totals).toEqual({ upgrades: 3, no_fix: 1, findings: 6 });
    expect(out!.running_kernel).toBe("6.8.0-45-generic");
    expect(out!.reboot_after_upgrade).toBe(true);
    expect(out!.upgrades[0]).toMatchObject({
      package: "openssl",
      binary_packages: ["libssl3", "openssl"],
      installed_versions: ["1.0-1", "3.0.13-0ubuntu3.1"],
      fixed_version: "3.0.13-0ubuntu3.10",
      requires_ubuntu_pro: false,
      kernel: false,
      top_severity: "critical",
      cve_count: 3,
      kev_count: 1,
      cves_cleared: 2,
      cves_unfixed: 1,
      dashboard_url: `${BASE}/dashboard/hosts/${HOST.id}/vulnerabilities?kind=package&q=openssl`,
    });
    expect((out!.upgrades[0].cves as unknown[])[0]).toEqual({
      id: "CVE-2024-1",
      severity: "critical",
      kev: true,
      fix: "standard",
      fixed_version: "3.0.13-0ubuntu3.4",
      dashboard_url: `${BASE}/dashboard/hosts/${HOST.id}/vulnerabilities?v=CVE-2024-1`,
    });
    expect(out!.upgrades[1]).toMatchObject({ package: "linux", kernel: true });
    expect(out!.upgrades[2]).toMatchObject({
      package: "libxml2",
      fixed_version: "2.9.13+dfsg-1ubuntu0.5+esm1",
      standard_fixed_version: null,
      requires_ubuntu_pro: true,
    });
    expect(out!.no_fix[0]).toMatchObject({ fixed_version: null, cves_cleared: 0, cves_unfixed: 1 });

    const text = resultText(res);
    expect(text).toContain("openssl 1.0-1, 3.0.13-0ubuntu3.1 -> 3.0.13-0ubuntu3.10");
    // Only the CVEs the upgrade clears are listed as cleared.
    expect(text).toContain("clears 2 CVE(s) [critical, 1 KEV]: CVE-2024-1 (KEV), CVE-2024-3.");
    expect(text).toContain("[kernel: reboot needed]");
    expect(text).toContain("needs Ubuntu Pro; without Pro: no fix in the normal archive");
    expect(text).toContain("1 CVE(s) have no fix yet and stay open");
    expect(text).toContain("No fix published yet:\n- vim 1.0-1: 1 CVE(s) [low]");
    // Data only: no command lines.
    expect(text).not.toMatch(/apt(-get)?\s|apk\s|sudo|dnf\s|yum\s/);
  });

  test("truncated: limit applies to upgrades and no_fix each", async () => {
    const many = [
      ...Array.from({ length: 4 }, (_, i) => finding(`CVE-2024-${i}`, `pkg${i}`)),
      ...Array.from({ length: 2 }, (_, i) =>
        finding(`CVE-2025-${i}`, `nofix${i}`, { fixedVersion: null, fixChannel: null }),
      ),
    ];
    const cut = await call({ host: "web-01", limit: 2 }, fakes(many));
    expect(cut.out!.upgrades.map((p) => p.package)).toEqual(["pkg0", "pkg1"]);
    expect(cut.out!.no_fix).toHaveLength(2);
    expect(cut.out).toMatchObject({ truncated: true, totals: { upgrades: 4, no_fix: 2 } });
    expect(cut.logged[0].resultItems).toBe(4);
    expect(resultText(cut.res)).toContain("2 more package(s) to upgrade; raise limit.");

    const all = await call({ host: "web-01", limit: 4 }, fakes(many));
    expect(all.out!.truncated).toBe(false);
  });

  test("a kernel package's CVEs are capped with a count of the rest", async () => {
    const kernelCves = Array.from({ length: 25 }, (_, i) =>
      finding(`CVE-2024-${100 + i}`, "linux", { kernelRelease: "6.8.0-45-generic" }),
    );
    const { out, res } = await call({ host: "web-01" }, fakes(kernelCves));
    expect(out!.upgrades[0]).toMatchObject({ cve_count: 25, more_cves: 5 });
    expect(out!.upgrades[0].cves as unknown[]).toHaveLength(20);
    expect(resultText(res)).toContain("CVE-2024-119 and 5 more");
  });

  test("nothing open", async () => {
    const { out, res } = await call({ host: "web-01", kev_only: true });
    expect(out).toMatchObject({ upgrades: [], no_fix: [], truncated: false });
    expect(resultText(res)).toContain("No open host package vulnerabilities on web-01");
  });
});
