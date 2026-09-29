"use client";

import type { FilterFn } from "@tanstack/react-table";

import { DataTable } from "@/components/data-table/data-table";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper, type DataTableFeatures } from "@/components/data-table/features";
import { Badge } from "@/components/ui/badge";
import type { HostUserRow } from "@/lib/queries-host-facts";

import { TimeAgo } from "../../table-cells";

// One scalar per user for the faceted filter, most privileged first.
type Access = "root" | "admin" | "login" | "nologin";
const ACCESS: { value: Access; label: string }[] = [
  { value: "root", label: "uid 0" },
  { value: "admin", label: "Admin group" },
  { value: "login", label: "Login shell" },
  { value: "nologin", label: "No login" },
];
const access = (u: HostUserRow): Access =>
  u.uid === 0 ? "root" : u.admin ? "admin" : u.loginShell ? "login" : "nologin";
const ACCESS_RANK: Record<Access, number> = {
  root: 0,
  admin: 1,
  login: 2,
  nologin: 3,
};

const ADMIN_GROUPS = new Set(["sudo", "wheel", "adm", "admin"]);

const col = dataTableColumnHelper<HostUserRow>();

const columns = col.columns([
  col.accessor("name", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="User" />,
    enableHiding: false,
    cell: ({ row }) => <span className="font-mono text-sm">{row.original.name}</span>,
  }),
  col.accessor("uid", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="UID" />,
    cell: ({ row }) => <span className="font-mono tabular-nums">{row.original.uid}</span>,
  }),
  col.accessor((u) => access(u), {
    id: "access",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Access" />,
    filterFn: "arrHas",
    sortFn: (a, b) => ACCESS_RANK[access(a.original)] - ACCESS_RANK[access(b.original)],
    cell: ({ row }) => {
      const u = row.original;
      return (
        <span className="inline-flex flex-wrap gap-1">
          {u.uid === 0 && <Badge variant="danger">uid 0</Badge>}
          {u.admin && u.uid !== 0 && <Badge variant="warning">Admin</Badge>}
          {u.loginShell ? (
            <Badge variant="outline">Login</Badge>
          ) : (
            <span className="text-muted-foreground text-xs">No login</span>
          )}
        </span>
      );
    },
  }),
  col.accessor((u) => u.groups.join(" "), {
    id: "groups",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Groups" />,
    enableSorting: false,
    cell: ({ row }) => (
      <span className="font-mono text-xs" title={row.original.groups.join(", ")}>
        {row.original.groups.map((g, i) => (
          <span key={g}>
            {i > 0 && ", "}
            <span className={ADMIN_GROUPS.has(g) ? "font-semibold" : undefined}>{g}</span>
          </span>
        ))}
      </span>
    ),
  }),
  col.accessor((u) => u.shell ?? "", {
    id: "shell",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Shell" />,
    cell: ({ row }) => (
      <span className="text-muted-foreground font-mono text-xs">{row.original.shell ?? "—"}</span>
    ),
  }),
  col.accessor((u) => u.home ?? "", {
    id: "home",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Home" />,
    cell: ({ row }) => (
      <span
        className="text-muted-foreground block max-w-64 truncate font-mono text-xs"
        title={row.original.home ?? undefined}
      >
        {row.original.home ?? "—"}
      </span>
    ),
  }),
  col.accessor("since", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Unchanged since" />,
    sortFn: (a, b) => Date.parse(a.original.since) - Date.parse(b.original.since),
    cell: ({ row }) => <TimeAgo iso={row.original.since} className="text-muted-foreground" />,
  }),
]);

const search: FilterFn<DataTableFeatures, HostUserRow> = (row, _id, value) => {
  const q = String(value ?? "")
    .trim()
    .toLowerCase();
  if (!q) return true;
  const u = row.original;
  return (
    u.name.toLowerCase().includes(q) ||
    String(u.uid) === q ||
    u.groups.some((g) => g.toLowerCase().includes(q))
  );
};

export function UsersTable({ rows }: { rows: HostUserRow[] }) {
  return (
    <DataTable
      columns={columns}
      data={rows}
      getRowId={(u) => u.name}
      globalFilterFn={search}
      searchPlaceholder="Search users or groups"
      facets={[{ columnId: "access", title: "Access", options: ACCESS }]}
      initialSorting={[{ id: "access", desc: false }]}
      initialVisibility={{ home: false }}
      pageSize={50}
      emptyMessage="No users match."
    />
  );
}
