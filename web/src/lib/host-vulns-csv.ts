// Column layout and file name of the host Vulnerabilities CSV export.
// Pure (no DB), so it can be unit tested with fixtures.

import { type CsvCell, toCsv } from "./csv";
import { platformLabel } from "./image-key";
import type { ExportFindingRow } from "./queries-host-vulns-export";
import type { VulnKind } from "./vuln-tables";

const list = (xs: string[]): string => xs.join("; ");

// Fix availability as the page's filter names it.
function fixStatus(r: Pick<ExportFindingRow, "fixedVersion" | "fixChannel" | "requiresPro">) {
  if (r.fixedVersion === null) return "none";
  if (r.fixChannel === "standard") return "available";
  if (r.requiresPro || r.fixChannel === "ubuntu-pro") return "ubuntu-pro";
  return r.fixChannel ?? "available";
}

const KIND: Record<VulnKind, string> = { package: "host package", image: "container image" };

const COLUMNS: [header: string, cell: (r: ExportFindingRow) => CsvCell][] = [
  ["Vulnerability ID", (r) => r.vulnKey],
  ["Aliases", (r) => list(r.aliases)],
  ["Advisories", (r) => list(r.advisoryIds)],
  ["Status", (r) => r.status],
  ["Severity", (r) => r.severity],
  ["Distro severity", (r) => r.distroSeverity],
  ["CVSS v3 score", (r) => r.cvssV3Score],
  ["CVSS v3 vector", (r) => r.cvssV3Vector],
  ["EPSS score", (r) => r.epssScore],
  ["EPSS percentile", (r) => r.epssPercentile],
  ["Known exploited (KEV)", (r) => (r.isKev ? "yes" : "no")],
  ["KEV added", (r) => r.kevAddedAt],
  ["KEV due date", (r) => r.kevDueDate],
  // Where: a host package, or a package inside one of the host's images
  // (empty image columns on host package rows).
  ["Kind", (r) => KIND[r.kind]],
  ["Image", (r) => list(r.imageRefs)],
  ["Image ID", (r) => r.image?.imageId ?? null],
  ["Platform", (r) => (r.image ? platformLabel(r.image) : null)],
  ["Containers", (r) => list(r.containers)],
  ["Source package", (r) => r.sourcePackage],
  ["Binary packages", (r) => list(r.packages)],
  ["Installed version", (r) => r.installedVersion],
  ["Fixed version", (r) => r.fixedVersion],
  ["Fix status", fixStatus],
  ["Fix advisory", (r) => r.fixAdvisoryId],
  ["Kernel release", (r) => r.kernelRelease],
  ["Running kernel unknown", (r) => (r.runningKernelUnknown ? "yes" : "no")],
  ["Published", (r) => r.publishedAt],
  ["First detected", (r) => r.firstSeenAt],
  ["Reopened", (r) => r.reopenedAt],
  ["Reopen count", (r) => r.reopenCount],
  ["Resolved", (r) => r.resolvedAt],
  ["Description", (r) => r.description],
];

export const HOST_VULNS_CSV_HEADER: readonly string[] = COLUMNS.map(([h]) => h);

export function hostVulnsCsv(rows: readonly ExportFindingRow[]): string {
  return toCsv(
    HOST_VULNS_CSV_HEADER,
    rows.map((r) => COLUMNS.map(([, cell]) => cell(r))),
  );
}

// <hostname>-vulnerabilities-<YYYY-MM-DD>.csv (UTC date). The hostname is
// reported by the agent, so anything outside [A-Za-z0-9._-] is replaced to
// keep the Content-Disposition header plain ASCII and free of quotes.
export function hostVulnsCsvFilename(hostname: string, now: Date = new Date()): string {
  const safe = hostname.replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^[._]+/, "") || "host";
  return `${safe}-vulnerabilities-${now.toISOString().slice(0, 10)}.csv`;
}
