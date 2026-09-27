"use client";

import type { FilterFn } from "@tanstack/react-table";

import { DataTable } from "@/components/data-table/data-table";
import type { DataTableFeatures } from "@/components/data-table/features";
import type { HostListRow } from "@/lib/queries";

import { hostColumns, STATE_OPTIONS } from "./host-columns";

// Search matches hostname, label or any collecting agent's name.
const searchHosts: FilterFn<DataTableFeatures, HostListRow> = (row, _columnId, value) => {
  const q = String(value ?? "")
    .trim()
    .toLowerCase();
  if (!q) return true;
  const h = row.original;
  return (
    h.hostname.toLowerCase().includes(q) ||
    !!h.label?.toLowerCase().includes(q) ||
    h.agents.some((a) => a.name.toLowerCase().includes(q))
  );
};

// Client-side mode (few hosts per account). Archived hosts are loaded but
// filtered out by default through the State facet.
export function HostsTable({ hosts }: { hosts: HostListRow[] }) {
  return (
    <DataTable
      columns={hostColumns}
      data={hosts}
      getRowId={(h) => h.id}
      globalFilterFn={searchHosts}
      searchPlaceholder="Search hosts or agents"
      facets={[{ columnId: "state", title: "State", options: STATE_OPTIONS }]}
      initialColumnFilters={[{ id: "state", value: ["active"] }]}
      initialVisibility={{ createdAt: false, state: false }}
      emptyMessage="No hosts match."
    />
  );
}
