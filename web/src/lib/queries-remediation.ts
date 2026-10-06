import { pool } from "./db";
import { compareDebVersions } from "./debversion";
import { isUuid } from "./queries-inventory";
import { getHostKernels, type KernelPackage } from "./queries-vulns";
import type { Severity } from "./severity";

// A host's remediation plan (docs/MCP.md#tools, get_host_remediation): its
// open host package findings (vulnerable_package; the same rows and
// filters as the host Vulnerabilities tab) grouped by source package, one
// entry per package to upgrade. Data only: packages and versions, never a
// command line, so distro quirks (held packages, pinned repos) stay with
// whoever runs the upgrade.
//
// Tenancy as in queries-vulns.ts: the read starts from the workspace's
// hosts (`h.workspace_id = $1`).

export type RemediationFinding = {
  vulnKey: string;
  sourcePackage: string;
  packages: string[];
  installedVersion: string | null;
  fixedVersion: string | null;
  // 'standard' (normal archive), 'ubuntu-pro' (only Ubuntu Pro / ESM has
  // a fix) or null (no fix published).
  fixChannel: "standard" | "ubuntu-pro" | null;
  severity: string | null;
  isKev: boolean;
  kernelRelease: string | null;
};

export type RemediationCve = {
  vulnKey: string;
  severity: string | null;
  isKev: boolean;
  fixChannel: RemediationFinding["fixChannel"];
  fixedVersion: string | null;
};

export type RemediationPackage = {
  sourcePackage: string;
  // Installed binaries built from it, from the findings.
  packages: string[];
  // Usually one; several while a host has more than one version of a
  // source's binaries installed.
  installedVersions: string[];
  // Highest fixed version across the package's fixed findings (standard
  // or Ubuntu Pro): installing it clears every finding that has a fix.
  fixedVersion: string | null;
  // Highest fixed version in the normal archive; null when only Ubuntu Pro
  // has fixes. Equal to fixedVersion unless requiresUbuntuPro.
  standardFixedVersion: string | null;
  // Reaching fixedVersion needs Ubuntu Pro: some finding's only fix is in
  // Pro, at a version above the normal archive's.
  requiresUbuntuPro: boolean;
  // A kernel package: the upgrade takes effect after a reboot.
  kernel: boolean;
  // Most urgent first (the query's order).
  cves: RemediationCve[];
  kev: number;
  // Findings on the package without a fix yet; they stay open after the
  // upgrade.
  unfixed: number;
  topSeverity: string | null;
};

export type HostRemediation = {
  // Packages with at least one fixed finding, most urgent finding first.
  upgrades: RemediationPackage[];
  // Packages where no finding has a fix yet.
  noFix: RemediationPackage[];
  // The running kernel (`uname -r`) from the newest snapshot by
  // collected_at, the matcher's rule; null = unknown.
  runningKernel: string | null;
};

export type RemediationFilters = { severities: Severity[] | null; kev: boolean };

// dpkg ordering; versions dpkg rejects fall back to plain text order so a
// malformed one never hides a valid one.
function compareVersions(a: string, b: string): number {
  return compareDebVersions(a, b) ?? (a < b ? -1 : a > b ? 1 : 0);
}

function highest(versions: (string | null)[]): string | null {
  let best: string | null = null;
  for (const v of versions)
    if (v !== null && (best === null || compareVersions(v, best) > 0)) best = v;
  return best;
}

// Groups findings (most urgent first) by source package. A package is a
// kernel when a finding came from a kernel binary (kernel_release set) or
// its source is one of the host's installed kernels' (getHostKernels).
export function groupRemediation(
  findings: RemediationFinding[],
  kernels: KernelPackage[],
): Omit<HostRemediation, "runningKernel"> {
  const kernelSources = new Set(kernels.flatMap((k) => (k.sourcePackage ? [k.sourcePackage] : [])));
  const groups = new Map<string, RemediationFinding[]>();
  for (const f of findings) {
    const list = groups.get(f.sourcePackage);
    if (list) list.push(f);
    else groups.set(f.sourcePackage, [f]);
  }

  const upgrades: RemediationPackage[] = [];
  const noFix: RemediationPackage[] = [];
  for (const [sourcePackage, rows] of groups) {
    const fixedVersion = highest(rows.map((r) => r.fixedVersion));
    const standardFixedVersion = highest(
      rows.map((r) => (r.fixChannel === "standard" ? r.fixedVersion : null)),
    );
    const pkg: RemediationPackage = {
      sourcePackage,
      packages: [...new Set(rows.flatMap((r) => r.packages))].toSorted(),
      installedVersions: [
        ...new Set(rows.flatMap((r) => (r.installedVersion ? [r.installedVersion] : []))),
      ].toSorted(compareVersions),
      fixedVersion,
      standardFixedVersion,
      requiresUbuntuPro:
        fixedVersion !== null &&
        (standardFixedVersion === null || compareVersions(fixedVersion, standardFixedVersion) > 0),
      kernel: kernelSources.has(sourcePackage) || rows.some((r) => r.kernelRelease !== null),
      cves: rows.map((r) => ({
        vulnKey: r.vulnKey,
        severity: r.severity,
        isKev: r.isKev,
        fixChannel: r.fixChannel,
        fixedVersion: r.fixedVersion,
      })),
      kev: rows.filter((r) => r.isKev).length,
      unfixed: rows.filter((r) => r.fixedVersion === null).length,
      topSeverity: rows[0].severity,
    };
    (fixedVersion === null ? noFix : upgrades).push(pkg);
  }

  return { upgrades, noFix };
}

// As getHost's runningKernel and host_kernel_packages: the newest snapshot
// by collected_at.
async function getRunningKernel(workspaceId: string, hostId: string): Promise<string | null> {
  if (!isUuid(hostId)) return null;
  const { rows } = await pool.query<{ kernel_release: string | null }>(
    `SELECT s.kernel_release
     FROM hosts h
     JOIN snapshots s ON s.host_id = h.id
     WHERE h.id = $2 AND h.workspace_id = $1
     ORDER BY s.collected_at DESC   -- snapshots_host_collected_idx
     LIMIT 1`,
    [workspaceId, hostId],
  );
  return rows[0]?.kernel_release ?? null;
}

export async function getHostRemediationFindings(
  workspaceId: string,
  hostId: string,
  f: RemediationFilters,
): Promise<RemediationFinding[]> {
  if (!isUuid(hostId)) return [];
  const { rows } = await pool.query<{
    vuln_key: string;
    source_package: string;
    packages: string[];
    installed_version: string | null;
    fixed_version: string | null;
    fix_channel: "standard" | "ubuntu-pro" | null;
    severity: string | null;
    is_kev: boolean;
    kernel_release: string | null;
  }>(
    // The host tab's open + severity order (findings_host_open_rank_idx).
    `SELECT f.vuln_key, coalesce(f.source_package, f.packages[1], '') AS source_package,
            f.packages, f.installed_version, f.fixed_version, f.fix_channel, f.severity,
            f.is_kev, f.kernel_release
     FROM hosts h
     JOIN findings f ON f.host_id = h.id
     WHERE h.id = $2 AND h.workspace_id = $1
       AND f.kind = 'vulnerable_package' AND f.status = 'open'
       AND ($3::text[] IS NULL OR f.severity = ANY($3))
       AND (NOT $4::boolean OR f.is_kev)
     ORDER BY f.severity_key DESC, f.vuln_key, f.source_package`,
    [workspaceId, hostId, f.severities, f.kev],
  );
  return rows.map((r) => ({
    vulnKey: r.vuln_key,
    sourcePackage: r.source_package,
    packages: r.packages,
    installedVersion: r.installed_version,
    fixedVersion: r.fixed_version,
    fixChannel: r.fix_channel,
    severity: r.severity,
    isKev: r.is_kev,
    kernelRelease: r.kernel_release,
  }));
}

export async function getHostRemediation(
  workspaceId: string,
  hostId: string,
  f: RemediationFilters,
): Promise<HostRemediation> {
  const [findings, kernels, runningKernel] = await Promise.all([
    getHostRemediationFindings(workspaceId, hostId, f),
    getHostKernels(workspaceId, hostId),
    getRunningKernel(workspaceId, hostId),
  ]);
  return { ...groupRemediation(findings, kernels), runningKernel };
}
