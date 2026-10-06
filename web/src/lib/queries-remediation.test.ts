/// <reference types="bun" />

import { describe, expect, test } from "bun:test";

import { groupRemediation, type RemediationFinding } from "./queries-remediation";
import type { KernelPackage } from "./queries-vulns";

function finding(
  vulnKey: string,
  sourcePackage: string,
  over: Partial<RemediationFinding> = {},
): RemediationFinding {
  return {
    vulnKey,
    sourcePackage,
    packages: [sourcePackage],
    installedVersion: "1.0-1",
    fixedVersion: "1.0-2",
    fixChannel: "standard",
    severity: "high",
    isKev: false,
    kernelRelease: null,
    ...over,
  };
}

function kernel(over: Partial<KernelPackage> = {}): KernelPackage {
  return {
    softwareId: "1",
    name: "linux-image-6.8.0-45-generic",
    version: "6.8.0-45.45",
    arch: "amd64",
    sourcePackage: "linux",
    kernelRelease: "6.8.0-45-generic",
    isRunning: true,
    firstSeenAt: "2026-10-01T00:00:00.000Z",
    vulnCount: 3,
    fixableCount: 2,
    ...over,
  };
}

describe("groupRemediation", () => {
  test("several findings on one package: one entry, the highest fixed version in dpkg order", () => {
    const { upgrades, noFix } = groupRemediation(
      [
        finding("CVE-2024-1", "openssl", {
          severity: "critical",
          isKev: true,
          packages: ["libssl3"],
          installedVersion: "3.0.13-0ubuntu3.1",
          fixedVersion: "3.0.13-0ubuntu3.4",
        }),
        // Higher than 3.4 for dpkg, lower as plain text.
        finding("CVE-2024-2", "openssl", {
          packages: ["openssl", "libssl3"],
          installedVersion: "3.0.13-0ubuntu3.1",
          fixedVersion: "3.0.13-0ubuntu3.10",
        }),
        finding("CVE-2024-3", "openssl", {
          severity: "medium",
          installedVersion: "3.0.13-0ubuntu3.1",
          fixedVersion: "3.0.13-0ubuntu3.2",
        }),
      ],
      [],
    );
    expect(noFix).toEqual([]);
    expect(upgrades).toHaveLength(1);
    expect(upgrades[0]).toMatchObject({
      sourcePackage: "openssl",
      packages: ["libssl3", "openssl"],
      installedVersions: ["3.0.13-0ubuntu3.1"],
      fixedVersion: "3.0.13-0ubuntu3.10",
      standardFixedVersion: "3.0.13-0ubuntu3.10",
      requiresUbuntuPro: false,
      kernel: false,
      kev: 1,
      unfixed: 0,
      topSeverity: "critical",
    });
    expect(upgrades[0].cves.map((c) => c.vulnKey)).toEqual([
      "CVE-2024-1",
      "CVE-2024-2",
      "CVE-2024-3",
    ]);
  });

  test("mixed fixed and unfixed: the package is an upgrade, its unfixed CVEs counted; all-unfixed goes apart", () => {
    const { upgrades, noFix } = groupRemediation(
      [
        finding("CVE-2024-10", "curl", {
          fixedVersion: null,
          fixChannel: null,
          severity: "critical",
        }),
        finding("CVE-2024-11", "curl", { fixedVersion: "8.5.0-2ubuntu10.6" }),
        finding("CVE-2024-12", "vim", { fixedVersion: null, fixChannel: null }),
        finding("CVE-2024-13", "vim", { fixedVersion: null, fixChannel: null, isKev: true }),
      ],
      [],
    );
    expect(upgrades.map((p) => p.sourcePackage)).toEqual(["curl"]);
    expect(upgrades[0]).toMatchObject({ fixedVersion: "8.5.0-2ubuntu10.6", unfixed: 1 });
    expect(upgrades[0].cves.map((c) => [c.vulnKey, c.fixChannel])).toEqual([
      ["CVE-2024-10", null],
      ["CVE-2024-11", "standard"],
    ]);
    expect(noFix).toHaveLength(1);
    expect(noFix[0]).toMatchObject({
      sourcePackage: "vim",
      fixedVersion: null,
      standardFixedVersion: null,
      requiresUbuntuPro: false,
      kev: 1,
      unfixed: 2,
    });
  });

  test("Ubuntu Pro: a Pro-only fix above the archive's needs Pro; Pro alone has no standard version", () => {
    const { upgrades } = groupRemediation(
      [
        finding("CVE-2024-20", "libxml2", { fixedVersion: "2.9.13+dfsg-1ubuntu0.4" }),
        finding("CVE-2024-21", "libxml2", {
          fixedVersion: "2.9.13+dfsg-1ubuntu0.5+esm1",
          fixChannel: "ubuntu-pro",
        }),
        finding("CVE-2024-22", "python2.7", {
          fixedVersion: "2.7.18-13ubuntu1.5+esm1",
          fixChannel: "ubuntu-pro",
        }),
        // A Pro fix the archive's version already passes doesn't need Pro.
        finding("CVE-2024-23", "zlib", { fixedVersion: "1:1.3.dfsg-3.1ubuntu2.1" }),
        finding("CVE-2024-24", "zlib", {
          fixedVersion: "1:1.3.dfsg-3.1ubuntu2",
          fixChannel: "ubuntu-pro",
        }),
      ],
      [],
    );
    const by = Object.fromEntries(upgrades.map((p) => [p.sourcePackage, p]));
    expect(by.libxml2).toMatchObject({
      fixedVersion: "2.9.13+dfsg-1ubuntu0.5+esm1",
      standardFixedVersion: "2.9.13+dfsg-1ubuntu0.4",
      requiresUbuntuPro: true,
    });
    expect(by["python2.7"]).toMatchObject({
      fixedVersion: "2.7.18-13ubuntu1.5+esm1",
      standardFixedVersion: null,
      requiresUbuntuPro: true,
    });
    expect(by.zlib).toMatchObject({
      fixedVersion: "1:1.3.dfsg-3.1ubuntu2.1",
      requiresUbuntuPro: false,
    });
  });

  test("kernel: from a kernel binary's finding, or the host's installed kernels' source", () => {
    const { upgrades } = groupRemediation(
      [
        finding("CVE-2024-30", "linux", {
          packages: ["linux-image-6.8.0-45-generic", "linux-modules-6.8.0-45-generic"],
          installedVersion: "6.8.0-45.45",
          fixedVersion: "6.8.0-50.50",
          kernelRelease: "6.8.0-45-generic",
        }),
        // No kernel_release on the finding, but getHostKernels knows the source.
        finding("CVE-2024-31", "linux-hwe-6.8", { kernelRelease: null }),
        finding("CVE-2024-32", "bash"),
      ],
      [
        kernel({
          sourcePackage: "linux-hwe-6.8",
          isRunning: false,
          kernelRelease: "6.8.0-40-generic",
        }),
        kernel(),
      ],
    );
    expect(upgrades.map((p) => [p.sourcePackage, p.kernel])).toEqual([
      ["linux", true],
      ["linux-hwe-6.8", true],
      ["bash", false],
    ]);
  });

  test("while the running kernel is unknown, every installed kernel's version is listed, in order", () => {
    const { upgrades } = groupRemediation(
      [
        finding("CVE-2024-40", "linux", {
          installedVersion: "6.8.0-45.45",
          kernelRelease: "6.8.0-45-generic",
        }),
        finding("CVE-2024-40", "linux", {
          installedVersion: "6.8.0-40.40",
          kernelRelease: "6.8.0-40-generic",
        }),
      ],
      [kernel({ isRunning: null })],
    );
    expect(upgrades[0]).toMatchObject({ kernel: true, fixedVersion: "1.0-2" });
    expect(upgrades[0].installedVersions).toEqual(["6.8.0-40.40", "6.8.0-45.45"]);
  });

  test("packages keep the order of their most urgent finding", () => {
    const { upgrades } = groupRemediation(
      [finding("CVE-1", "b"), finding("CVE-2", "a"), finding("CVE-3", "b"), finding("CVE-4", "c")],
      [],
    );
    expect(upgrades.map((p) => p.sourcePackage)).toEqual(["b", "a", "c"]);
  });

  test("nothing open: nothing to do", () => {
    expect(groupRemediation([], [])).toEqual({ upgrades: [], noFix: [] });
  });
});
