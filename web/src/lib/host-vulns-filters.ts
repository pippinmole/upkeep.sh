// URL filters of the host Vulnerabilities tab, as the CSV export reads
// them. They mirror the page's own parsing (hosts/[hostId]/vulnerabilities/
// page.tsx) so the export selects exactly the rows the table shows, minus
// pagination. Kept apart from queries-vulns.ts so the export stays
// self-contained.

import { oneOf, param, type SearchParams } from "./search-params";
import { SEVERITIES, type Severity } from "./severity";

export type HostVulnFixFilter = "available" | "pro" | "none";

export type HostVulnFilters = {
  status: "open" | "resolved";
  q: string | null; // vuln key, source or binary package substring
  severity: Severity | null;
  kev: boolean;
  fix: HostVulnFixFilter | null;
  sort: "severity" | "recent";
};

export function parseHostVulnFilters(sp: SearchParams): HostVulnFilters {
  return {
    status: oneOf(sp, "status", ["open", "resolved"] as const) ?? "open",
    q: param(sp, "q"),
    severity: oneOf(sp, "severity", SEVERITIES),
    kev: param(sp, "kev") === "1",
    fix: oneOf<HostVulnFixFilter>(sp, "fix", ["available", "pro", "none"]),
    sort: oneOf(sp, "sort", ["severity", "recent"] as const) ?? "severity",
  };
}

// True when a filter narrows the status tab (sort and status don't count).
export function hasHostVulnFilters(f: HostVulnFilters): boolean {
  return !!(f.q || f.severity || f.kev || f.fix);
}

// URLSearchParams -> the page's SearchParams shape (first value wins).
export function searchParamsOf(u: URLSearchParams): SearchParams {
  const sp: SearchParams = {};
  for (const [k, v] of u) if (!(k in sp)) sp[k] = v;
  return sp;
}
