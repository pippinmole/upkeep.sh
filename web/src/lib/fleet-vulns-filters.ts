// URL filters of the fleet Vulnerabilities list (a server-driven DataTable,
// vuln-tables.ts), parsed once here for the page and the MCP tools
// (lib/mcp/tools/vulnerabilities.ts), so list_top_vulnerabilities and the
// dashboard select and order rows the same way for the same filters.

import type { DataTableServerState } from "@/components/data-table/data-table";
import { tableFacet, tableSort, tableStateFromParams } from "@/components/data-table/url-params";

import type { FleetVulnListFilters } from "./queries-vuln-list";
import { oneOf, type SearchParams } from "./search-params";
import { SEVERITIES } from "./severity";
import { FLEET_VULN_SORTS, fleetVulnsTable, VULN_FIXES, VULN_KINDS } from "./vuln-tables";

export type FleetVulnFilters = Omit<FleetVulnListFilters, "page" | "pageSize">;

export function parseFleetVulnFilters(sp: SearchParams): {
  state: DataTableServerState;
  filters: FleetVulnFilters;
} {
  const status = oneOf(sp, "status", ["open", "resolved"] as const) ?? "open";
  const state = tableStateFromParams(sp, fleetVulnsTable(status));
  return {
    state,
    filters: {
      status,
      q: state.globalFilter || null,
      kinds: tableFacet(state, "kind", VULN_KINDS),
      severities: tableFacet(state, "severity", SEVERITIES),
      kev: tableFacet(state, "kev", ["1"]) !== null,
      // Resolved rows have no Fix facet: the fix data is from when they were open.
      fix: status === "open" ? tableFacet(state, "fix", VULN_FIXES) : null,
      sort: tableSort(state, FLEET_VULN_SORTS, status === "resolved" ? "seen" : "severity"),
    },
  };
}
