// URL filters of the host Vulnerabilities tab (a server-driven DataTable,
// vuln-tables.ts), parsed once here for both the page and the CSV export
// so the export selects exactly the rows the table lists, minus
// pagination.

import type { DataTableServerState } from "@/components/data-table/data-table";
import { tableFacet, tableSort, tableStateFromParams } from "@/components/data-table/url-params";

import type { HostVulnListFilters } from "./queries-vuln-list";
import { oneOf, type SearchParams } from "./search-params";
import { SEVERITIES } from "./severity";
import { HOST_VULN_SORTS, hostVulnsTable, VULN_FIXES, VULN_KINDS } from "./vuln-tables";

export type HostVulnFilters = Omit<HostVulnListFilters, "page" | "pageSize">;

export function parseHostVulnFilters(sp: SearchParams): {
  state: DataTableServerState;
  filters: HostVulnFilters;
} {
  const status = oneOf(sp, "status", ["open", "resolved"] as const) ?? "open";
  const state = tableStateFromParams(sp, hostVulnsTable(status));
  return {
    state,
    filters: {
      status,
      q: state.globalFilter || null,
      kinds: tableFacet(state, "kind", VULN_KINDS),
      severities: tableFacet(state, "severity", SEVERITIES),
      kev: tableFacet(state, "kev", ["1"]) !== null,
      fix: tableFacet(state, "fix", VULN_FIXES),
      sort: tableSort(state, HOST_VULN_SORTS, status === "resolved" ? "seen" : "severity"),
    },
  };
}

// True when a filter narrows the status tab (sort and status don't count).
export function hasHostVulnFilters(f: HostVulnFilters): boolean {
  return !!(f.q || f.kinds || f.severities || f.kev || f.fix);
}

// URLSearchParams -> the page's SearchParams shape (first value wins).
export function searchParamsOf(u: URLSearchParams): SearchParams {
  const sp: SearchParams = {};
  for (const [k, v] of u) if (!(k in sp)) sp[k] = v;
  return sp;
}
