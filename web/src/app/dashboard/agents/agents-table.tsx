"use client";

import type { FilterFn } from "@tanstack/react-table";

import { DataTable } from "@/components/data-table/data-table";
import type { DataTableFeatures } from "@/components/data-table/features";
import type { AgentWithHosts } from "@/lib/queries";

import { agentColumns, STATUS_OPTIONS } from "./agent-columns";
import { AgentHosts } from "./agent-hosts";

// Search matches the agent name or any of its hosts' hostname / label.
const searchAgentsAndHosts: FilterFn<DataTableFeatures, AgentWithHosts> = (
  row,
  _columnId,
  value,
) => {
  const q = String(value ?? "")
    .trim()
    .toLowerCase();
  if (!q) return true;
  const a = row.original;
  return (
    a.name.toLowerCase().includes(q) ||
    a.hosts.some(
      (h) => h.hostname.toLowerCase().includes(q) || !!h.label?.toLowerCase().includes(q),
    )
  );
};

// Client-side mode: an account has few agents, so all of them (and their
// hosts) are loaded by the page and sorted / filtered in the browser.
export function AgentsTable({
  agents,
  initialSearch,
}: {
  agents: AgentWithHosts[];
  initialSearch?: string;
}) {
  return (
    <DataTable
      columns={agentColumns}
      data={agents}
      getRowId={(a) => a.id}
      getRowCanExpand={() => true}
      renderSubRows={(row) => <AgentHosts agent={row.original} />}
      globalFilterFn={searchAgentsAndHosts}
      initialGlobalFilter={initialSearch}
      searchPlaceholder="Search agents or hosts"
      facets={[{ columnId: "status", title: "Status", options: STATUS_OPTIONS }]}
      initialVisibility={{ createdAt: false }}
      emptyMessage="No agents match."
    />
  );
}
