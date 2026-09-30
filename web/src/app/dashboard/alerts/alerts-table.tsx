"use client";

import { DataTable, type DataTableServerState } from "@/components/data-table/data-table";
import { useServerTable } from "@/components/data-table/url-state";
import { ALERT_STATE_LABEL, ALERTS_TABLE } from "@/lib/alerts-table";
import type { AlertFacets, AlertRow } from "@/lib/queries-alerts";

import { alertColumns } from "./alert-columns";

// Server-driven: alert history grows without bound (a vulnerability rule
// alone can fire hundreds of times), so search, facets, sort and paging
// are URL params the Server Component turns into SQL.
export function AlertsTable({
  rows,
  total,
  state,
  facets,
}: {
  rows: AlertRow[];
  total: number;
  state: DataTableServerState;
  facets: AlertFacets;
}) {
  const server = useServerTable(state, total, ALERTS_TABLE);
  return (
    <DataTable
      columns={alertColumns}
      data={rows}
      getRowId={(r) => r.id}
      server={server}
      searchPlaceholder="Search alerts, hosts, rules"
      facets={[
        {
          columnId: "state",
          title: "State",
          options: facets.states.map((s) => ({
            value: s.value,
            label: `${ALERT_STATE_LABEL[s.value]} (${s.count})`,
          })),
        },
        {
          columnId: "rule",
          title: "Rule",
          options: facets.rules.map((r) => ({ value: r.id, label: `${r.name} (${r.count})` })),
        },
        {
          columnId: "host",
          title: "Host",
          options: facets.hosts.map((h) => ({ value: h.id, label: `${h.name} (${h.count})` })),
        },
      ]}
      emptyMessage="No alerts match these filters."
    />
  );
}
