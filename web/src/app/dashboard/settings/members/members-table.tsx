"use client";

import { DataTable } from "@/components/data-table/data-table";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import { Badge } from "@/components/ui/badge";
import { useViewer } from "@/components/viewer-context";
import type { MemberRow } from "@/lib/queries-members";
import { ROLE_LABELS, ROLES } from "@/lib/roles";
import { relativeTime } from "@/lib/time";

import { MemberRowActions } from "./member-row-actions";

const ROLE_OPTIONS = ROLES.map((r) => ({ value: r, label: ROLE_LABELS[r] }));

const col = dataTableColumnHelper<MemberRow>();

function columns(currentUserId: string, isAdmin: boolean) {
  return col.columns([
    col.accessor((m) => m.username ?? m.email, {
      id: "username",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Username" />,
      enableHiding: false,
      cell: ({ row }) => (
        <span className="inline-flex items-center gap-2 font-medium">
          {row.original.username ?? "—"}
          {row.original.id === currentUserId && <Badge variant="neutral">You</Badge>}
        </span>
      ),
    }),
    col.accessor("name", {
      header: ({ column }) => <DataTableColumnHeader column={column} title="Name" />,
      cell: ({ getValue }) => getValue() || <span className="text-muted-foreground">—</span>,
    }),
    col.accessor("email", {
      header: ({ column }) => <DataTableColumnHeader column={column} title="Email" />,
      cell: ({ getValue }) => <span className="text-muted-foreground">{getValue()}</span>,
    }),
    col.accessor("role", {
      header: ({ column }) => <DataTableColumnHeader column={column} title="Role" />,
      filterFn: "arrHas",
      cell: ({ row }) => (
        <Badge variant={row.original.role === "admin" ? "info" : "outline"}>
          {ROLE_LABELS[row.original.role]}
        </Badge>
      ),
    }),
    col.accessor((m) => (m.disabled ? "disabled" : m.mustChangePassword ? "pending" : "active"), {
      id: "status",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Status" />,
      cell: ({ getValue }) => {
        const s = getValue();
        if (s === "disabled") return <Badge variant="neutral">Disabled</Badge>;
        if (s === "pending") return <Badge variant="warning">Temporary password</Badge>;
        return <Badge variant="success">Active</Badge>;
      },
    }),
    col.accessor((m) => (m.lastActiveAt ? Date.parse(m.lastActiveAt) : 0), {
      id: "lastActive",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Last active" />,
      cell: ({ row }) =>
        row.original.lastActiveAt ? (
          <span className="whitespace-nowrap">{relativeTime(row.original.lastActiveAt)}</span>
        ) : (
          <span className="text-muted-foreground">Never</span>
        ),
    }),
    col.accessor((m) => Date.parse(m.createdAt), {
      id: "createdAt",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Added" />,
      cell: ({ row }) => (
        <span className="whitespace-nowrap">{relativeTime(row.original.createdAt)}</span>
      ),
    }),
    ...(isAdmin
      ? [
          col.display({
            id: "actions",
            enableHiding: false,
            cell: ({ row }) =>
              row.original.id === currentUserId ? null : <MemberRowActions member={row.original} />,
          }),
        ]
      : []),
  ]);
}

export function MembersTable({
  members,
  currentUserId,
}: {
  members: MemberRow[];
  currentUserId: string;
}) {
  const { isAdmin } = useViewer();
  return (
    <DataTable
      columns={columns(currentUserId, isAdmin)}
      data={members}
      getRowId={(m) => m.id}
      searchPlaceholder="Search members"
      facets={[{ columnId: "role", title: "Role", options: ROLE_OPTIONS }]}
      emptyMessage="No members match."
    />
  );
}
