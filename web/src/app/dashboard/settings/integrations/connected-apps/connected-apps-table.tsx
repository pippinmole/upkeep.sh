"use client";

import { DataTable } from "@/components/data-table/data-table";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import { describeScope } from "@/lib/mcp/scopes";
import type { ConnectedAppRow } from "@/lib/queries-integrations";
import { formatDateTime, relativeTime } from "@/lib/time";

import { RevokeAppButton } from "./revoke-app-button";

const col = dataTableColumnHelper<ConnectedAppRow>();

function Time({ iso, never }: { iso: string | null; never: string }) {
  if (!iso) return <span className="text-muted-foreground">{never}</span>;
  return (
    <span className="whitespace-nowrap" title={formatDateTime(iso)}>
      {relativeTime(iso)}
    </span>
  );
}

function columns(isAdmin: boolean, currentUserId: string) {
  return col.columns([
    // Name over the CIMD metadata host, which says who publishes the client
    // (a name alone is whatever the client chose to call itself).
    col.accessor((a) => `${a.clientName} ${a.clientHost ?? ""}`.toLowerCase(), {
      id: "client",
      header: ({ column }) => <DataTableColumnHeader column={column} title="App" />,
      enableHiding: false,
      cell: ({ row }) => (
        <div className="flex min-w-0 flex-col">
          <span className="truncate font-medium">{row.original.clientName}</span>
          {row.original.clientHost && (
            <span className="text-muted-foreground truncate text-xs">
              {row.original.clientHost}
            </span>
          )}
        </div>
      ),
    }),
    ...(isAdmin
      ? [
          col.accessor((a) => (a.username ?? a.email ?? "").toLowerCase(), {
            id: "user",
            header: ({ column }) => <DataTableColumnHeader column={column} title="User" />,
            cell: ({ row }) => (
              <span className="whitespace-nowrap" title={row.original.email ?? undefined}>
                {row.original.username ?? row.original.email ?? "—"}
                {row.original.userId === currentUserId && (
                  <span className="text-muted-foreground ml-1.5 text-xs">(you)</span>
                )}
              </span>
            ),
          }),
        ]
      : []),
    col.accessor((a) => a.scopes.map(describeScope).join(" ").toLowerCase(), {
      id: "scopes",
      header: "Access",
      enableSorting: false,
      // Takes the space the others leave, so the table fits beside the
      // settings nav from lg; below lg it scrolls.
      meta: { className: "lg:w-full" },
      cell: ({ row }) => (
        <ul className="flex min-w-56 flex-col gap-0.5 text-sm">
          {row.original.scopes.map((s) => (
            <li key={s} title={s}>
              {describeScope(s)}
            </li>
          ))}
        </ul>
      ),
    }),
    col.accessor((a) => Date.parse(a.createdAt), {
      id: "createdAt",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Authorized" />,
      cell: ({ row }) => <Time iso={row.original.createdAt} never="—" />,
    }),
    col.accessor((a) => (a.lastUsedAt ? Date.parse(a.lastUsedAt) : 0), {
      id: "lastUsed",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Last used" />,
      cell: ({ row }) => <Time iso={row.original.lastUsedAt} never="Not yet" />,
    }),
    // Every row a viewer sees is one they may revoke: admins see all rows,
    // members only their own. The server checks again.
    col.display({
      id: "actions",
      enableHiding: false,
      meta: { className: "w-24 text-right" },
      cell: ({ row }) => (
        <RevokeAppButton app={row.original} isOwn={row.original.userId === currentUserId} />
      ),
    }),
  ]);
}

export function ConnectedAppsTable({
  apps,
  isAdmin,
  currentUserId,
}: {
  apps: ConnectedAppRow[];
  isAdmin: boolean;
  currentUserId: string;
}) {
  return (
    <DataTable
      columns={columns(isAdmin, currentUserId)}
      data={apps}
      getRowId={(a) => a.id}
      searchPlaceholder={isAdmin ? "Search apps and users" : "Search apps"}
      initialSorting={[{ id: "createdAt", desc: true }]}
    />
  );
}
