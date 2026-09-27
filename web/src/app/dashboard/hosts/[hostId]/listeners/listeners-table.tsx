"use client";

import type { FilterFn } from "@tanstack/react-table";

import { DataTable } from "@/components/data-table/data-table";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper, type DataTableFeatures } from "@/components/data-table/features";
import { Badge } from "@/components/ui/badge";
import type { HostListenerRow } from "@/lib/queries-host-facts";
import { formatDateTime, relativeTime } from "@/lib/time";

const TRANSPORTS = [
  { value: "tcp", label: "TCP" },
  { value: "udp", label: "UDP" },
];

type Binding = "all" | "loopback" | "address";
const BINDINGS: { value: Binding; label: string }[] = [
  { value: "all", label: "All interfaces" },
  { value: "address", label: "Specific address" },
  { value: "loopback", label: "Loopback only" },
];
const binding = (l: HostListenerRow): Binding =>
  l.wildcard ? "all" : l.loopback ? "loopback" : "address";
const BINDING_RANK: Record<Binding, number> = { all: 0, address: 1, loopback: 2 };

const col = dataTableColumnHelper<HostListenerRow>();

const columns = col.columns([
  col.accessor("port", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Port" />,
    enableHiding: false,
    cell: ({ row }) => <span className="font-mono tabular-nums">{row.original.port}</span>,
  }),
  col.accessor("transport", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Protocol" />,
    filterFn: "arrHas",
    cell: ({ row }) => <span className="font-mono text-xs uppercase">{row.original.proto}</span>,
  }),
  col.accessor("localAddr", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Address" />,
    cell: ({ row }) => <span className="font-mono text-xs">{row.original.localAddr}</span>,
  }),
  col.accessor((l) => binding(l), {
    id: "binding",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Bound to" />,
    filterFn: "arrHas",
    sortFn: (a, b) => BINDING_RANK[binding(a.original)] - BINDING_RANK[binding(b.original)],
    cell: ({ row }) => {
      const b = binding(row.original);
      return b === "all" ? (
        <Badge
          variant="outline"
          className="border-amber-600/40 bg-amber-400/15 whitespace-nowrap text-amber-900 dark:text-amber-200"
          title="Reachable on every network interface, subject to the host's firewall"
        >
          All interfaces
        </Badge>
      ) : (
        <span className="text-muted-foreground whitespace-nowrap">
          {BINDINGS.find((x) => x.value === b)?.label}
        </span>
      );
    },
  }),
  col.accessor((l) => l.processName ?? "", {
    id: "process",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Process" />,
    cell: ({ row }) =>
      row.original.processName ? (
        <span className="font-mono text-xs">{row.original.processName}</span>
      ) : (
        <span
          className="text-muted-foreground"
          title="The owning process couldn't be read (kernel socket, or another user's process)"
        >
          —
        </span>
      ),
  }),
  col.accessor("since", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Listening since" />,
    sortFn: (a, b) => Date.parse(a.original.since) - Date.parse(b.original.since),
    cell: ({ row }) => (
      <span
        className="text-muted-foreground whitespace-nowrap"
        title={formatDateTime(row.original.since)}
      >
        {relativeTime(row.original.since)}
      </span>
    ),
  }),
]);

const search: FilterFn<DataTableFeatures, HostListenerRow> = (row, _id, value) => {
  const q = String(value ?? "")
    .trim()
    .toLowerCase();
  if (!q) return true;
  const l = row.original;
  return (
    String(l.port) === q || l.localAddr.includes(q) || !!l.processName?.toLowerCase().includes(q)
  );
};

export function ListenersTable({ rows }: { rows: HostListenerRow[] }) {
  return (
    <DataTable
      columns={columns}
      data={rows}
      getRowId={(l) => l.key}
      globalFilterFn={search}
      searchPlaceholder="Search port, address or process"
      facets={[
        { columnId: "transport", title: "Protocol", options: TRANSPORTS },
        { columnId: "binding", title: "Bound to", options: BINDINGS },
      ]}
      initialSorting={[{ id: "port", desc: false }]}
      pageSize={50}
      emptyMessage="No listeners match."
    />
  );
}
