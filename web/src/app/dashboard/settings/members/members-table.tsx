"use client";

import { useEffect, useState } from "react";

import { DataTable } from "@/components/data-table/data-table";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import { Badge } from "@/components/ui/badge";
import { useViewer } from "@/components/viewer-context";
import type { MemberRow } from "@/lib/queries-members";
import { ROLE_LABELS, ROLES } from "@/lib/roles";
import { relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";

import { MemberCell } from "./member-cell";
import { MemberRowActions, OwnRowActions } from "./member-row-actions";
import { memberStatus, MemberStatusBadge, STATUS_OPTIONS } from "./member-status";

const ROLE_OPTIONS = ROLES.map((r) => ({ value: r, label: ROLE_LABELS[r] }));
const HIGHLIGHT_MS = 1500;

const col = dataTableColumnHelper<MemberRow>();

function columns(currentUserId: string, isAdmin: boolean, onChanged: (id: string) => void) {
  return col.columns([
    // One identity column; the joined value keeps name and email searchable
    // and sorts by username (it comes first).
    col.accessor((m) => `${m.username ?? m.email} ${m.name} ${m.email}`.toLowerCase(), {
      id: "member",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Member" />,
      enableHiding: false,
      // From lg the column takes the space the others leave and truncates,
      // so the table fits beside the settings nav; below lg it scrolls.
      meta: { className: "lg:w-full lg:max-w-0" },
      cell: ({ row }) => (
        <MemberCell member={row.original} isYou={row.original.id === currentUserId} />
      ),
    }),
    col.accessor("role", {
      header: ({ column }) => <DataTableColumnHeader column={column} title="Role" />,
      filterFn: "arrHas",
      cell: ({ row }) => (
        <Badge
          variant={row.original.role === "admin" ? "info" : "outline"}
          className="whitespace-nowrap"
        >
          {ROLE_LABELS[row.original.role]}
        </Badge>
      ),
    }),
    col.accessor(memberStatus, {
      id: "status",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Status" />,
      filterFn: "arrHas",
      cell: ({ getValue }) => <MemberStatusBadge status={getValue()} />,
    }),
    // From live sessions: resets and disables sign people out, so no
    // session doesn't mean they never signed in.
    col.accessor((m) => (m.lastActiveAt ? Date.parse(m.lastActiveAt) : 0), {
      id: "lastActive",
      // No room beside the settings nav between lg and xl.
      meta: { className: "lg:hidden xl:table-cell" },
      header: ({ column }) => <DataTableColumnHeader column={column} title="Last seen" />,
      cell: ({ row }) =>
        row.original.lastActiveAt ? (
          <span className="whitespace-nowrap">{relativeTime(row.original.lastActiveAt)}</span>
        ) : (
          <span className="text-muted-foreground" title="No active session">
            —
          </span>
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
            meta: { className: "w-12 text-right" },
            cell: ({ row }) =>
              row.original.id === currentUserId ? (
                <OwnRowActions />
              ) : (
                <MemberRowActions member={row.original} onChanged={onChanged} />
              ),
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
  // The row a role, status or password change just succeeded on, briefly
  // highlighted (there's no toast).
  const [changedId, setChangedId] = useState<string | null>(null);
  useEffect(() => {
    if (!changedId) return;
    const t = setTimeout(() => setChangedId(null), HIGHLIGHT_MS);
    return () => clearTimeout(t);
  }, [changedId]);

  return (
    <DataTable
      columns={columns(currentUserId, isAdmin, setChangedId)}
      data={members}
      getRowId={(m) => m.id}
      searchPlaceholder="Search members"
      facets={[
        { columnId: "role", title: "Role", options: ROLE_OPTIONS },
        { columnId: "status", title: "Status", options: STATUS_OPTIONS },
      ]}
      // Administrators first, so members can see whom to ask.
      initialSorting={[{ id: "role", desc: false }]}
      initialVisibility={{ createdAt: false }}
      getRowClassName={(m) =>
        cn(
          "duration-700",
          // The menu stays at full strength: it's how to enable them again.
          m.disabled && (isAdmin ? "[&>td:not(:last-child)]:opacity-60" : "[&>td]:opacity-60"),
          m.id === changedId && "bg-success/10 hover:bg-success/10",
        )
      }
    />
  );
}
