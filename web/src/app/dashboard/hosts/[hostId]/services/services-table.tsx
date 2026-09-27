"use client";

import type { FilterFn } from "@tanstack/react-table";

import { DataTable } from "@/components/data-table/data-table";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper, type DataTableFeatures } from "@/components/data-table/features";
import { Badge } from "@/components/ui/badge";
import type { HostServiceRow } from "@/lib/queries-host-facts";
import { formatDateTime, relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";

const STATE_OPTIONS = [
  { value: "running", label: "Running" },
  { value: "stopped", label: "Stopped" },
];

// PROTOCOL.md services.start_mode.
const START_MODES: { value: string; label: string; hint: string }[] = [
  { value: "auto", label: "Auto", hint: "Enabled: started at boot" },
  { value: "manual", label: "On demand", hint: "Started by a socket, timer or path unit" },
  { value: "static", label: "Static", hint: "No [Install] section: runs only as a dependency" },
  { value: "disabled", label: "Disabled", hint: "Can be enabled, but isn't" },
  { value: "masked", label: "Masked", hint: "Linked to /dev/null: can't be started" },
];
const MODE_RANK = Object.fromEntries(START_MODES.map((m, i) => [m.value, i]));

const col = dataTableColumnHelper<HostServiceRow>();

const columns = col.columns([
  col.accessor("name", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Service" />,
    enableHiding: false,
    cell: ({ row }) => (
      <div className="min-w-0">
        <div className="font-mono text-sm">{row.original.name}</div>
        {row.original.displayName && (
          <div className="text-muted-foreground max-w-80 truncate text-xs">
            {row.original.displayName}
          </div>
        )}
      </div>
    ),
  }),
  col.accessor((s) => s.state ?? "unknown", {
    id: "state",
    header: ({ column }) => <DataTableColumnHeader column={column} title="State" />,
    filterFn: "arrHas",
    cell: ({ row }) => {
      const s = row.original.state;
      if (!s) return <span className="text-muted-foreground">Unknown</span>;
      return (
        <Badge
          variant="outline"
          className={cn(
            "whitespace-nowrap",
            s === "running"
              ? "border-emerald-600/40 bg-emerald-500/10 text-emerald-800 dark:text-emerald-200"
              : "text-muted-foreground",
          )}
        >
          {s === "running" ? "Running" : "Stopped"}
        </Badge>
      );
    },
  }),
  col.accessor((s) => s.startMode ?? "", {
    id: "startMode",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Start mode" />,
    filterFn: "arrHas",
    sortFn: (a, b) =>
      (MODE_RANK[a.original.startMode ?? ""] ?? 99) - (MODE_RANK[b.original.startMode ?? ""] ?? 99),
    cell: ({ row }) => {
      const m = START_MODES.find((x) => x.value === row.original.startMode);
      if (!m) return <span className="text-muted-foreground">{row.original.startMode ?? "—"}</span>;
      const title = row.original.activatedBy ? `${m.hint} (${row.original.activatedBy})` : m.hint;
      return (
        <span title={title} className={cn(m.value === "masked" && "text-muted-foreground")}>
          {m.label}
          {row.original.activatedBy && (
            <span className="text-muted-foreground ml-1 font-mono text-xs">
              via {row.original.activatedBy}
            </span>
          )}
        </span>
      );
    },
  }),
  col.accessor((s) => s.runAs ?? "", {
    id: "runAs",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Runs as" />,
    cell: ({ row }) => (
      <span className="font-mono text-xs">{row.original.runAs ?? "—"}</span>
    ),
  }),
  col.accessor((s) => s.binaryPath ?? "", {
    id: "binaryPath",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Binary" />,
    cell: ({ row }) => (
      <span
        className="text-muted-foreground block max-w-72 truncate font-mono text-xs"
        title={row.original.binaryPath ?? undefined}
      >
        {row.original.binaryPath ?? "—"}
      </span>
    ),
  }),
  col.accessor("since", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="In this state since" />,
    sortFn: (a, b) => Date.parse(a.original.since) - Date.parse(b.original.since),
    cell: ({ row }) => (
      <span className="text-muted-foreground whitespace-nowrap" title={formatDateTime(row.original.since)}>
        {relativeTime(row.original.since)}
      </span>
    ),
  }),
]);

const search: FilterFn<DataTableFeatures, HostServiceRow> = (row, _id, value) => {
  const q = String(value ?? "")
    .trim()
    .toLowerCase();
  if (!q) return true;
  const s = row.original;
  return [s.name, s.displayName, s.binaryPath, s.runAs].some((v) => v?.toLowerCase().includes(q));
};

// Client-side mode: a host has at most a few hundred units.
export function ServicesTable({ rows }: { rows: HostServiceRow[] }) {
  return (
    <DataTable
      columns={columns}
      data={rows}
      getRowId={(s) => s.key}
      globalFilterFn={search}
      searchPlaceholder="Search services"
      facets={[
        { columnId: "state", title: "State", options: STATE_OPTIONS },
        { columnId: "startMode", title: "Start mode", options: START_MODES },
      ]}
      initialSorting={[{ id: "name", desc: false }]}
      pageSize={50}
      emptyMessage="No services match."
    />
  );
}
