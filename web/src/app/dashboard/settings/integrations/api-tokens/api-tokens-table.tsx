"use client";

import { DataTable } from "@/components/data-table/data-table";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import { Badge } from "@/components/ui/badge";
import type { ApiTokenRow } from "@/lib/queries-integrations";
import { formatDate, formatDateTime, relativeTime } from "@/lib/time";

import { RevokeTokenButton } from "./revoke-token-button";

const col = dataTableColumnHelper<ApiTokenRow>();

function Time({ iso, never }: { iso: string | null; never: string }) {
  if (!iso) return <span className="text-muted-foreground">{never}</span>;
  return (
    <span className="whitespace-nowrap" title={formatDateTime(iso)}>
      {relativeTime(iso)}
    </span>
  );
}

// The expiry date, with a badge from 7 days before. The state comes from
// the server, so it doesn't depend on the browser's clock.
function Expires({ token }: { token: ApiTokenRow }) {
  if (!token.expiresAt) return <span className="text-muted-foreground">Never</span>;
  return (
    <span
      className="flex items-center gap-2 whitespace-nowrap"
      title={formatDateTime(token.expiresAt)}
    >
      {formatDate(token.expiresAt)}
      {token.state === "expiring" && <Badge variant="warning">Expiring soon</Badge>}
      {token.state === "expired" && <Badge variant="danger">Expired</Badge>}
    </span>
  );
}

function columns(isAdmin: boolean, currentUserId: string) {
  return col.columns([
    // The name over the token's first characters, which is how a token in
    // a config file can be matched to its row.
    col.accessor((t) => `${t.name} ${t.start ?? ""}`.toLowerCase(), {
      id: "name",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Name" />,
      enableHiding: false,
      // Takes the space the others leave, so the table fits beside the
      // settings nav from lg; below lg it scrolls.
      meta: { className: "lg:w-full" },
      cell: ({ row }) => (
        <div className="flex min-w-0 flex-col">
          <span className="truncate font-medium">{row.original.name}</span>
          {row.original.start && (
            <code className="text-muted-foreground truncate text-xs">{row.original.start}…</code>
          )}
        </div>
      ),
    }),
    ...(isAdmin
      ? [
          col.accessor((t) => (t.username ?? t.email ?? "").toLowerCase(), {
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
    col.accessor((t) => Date.parse(t.createdAt), {
      id: "createdAt",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Created" />,
      cell: ({ row }) => <Time iso={row.original.createdAt} never="—" />,
    }),
    col.accessor((t) => (t.lastUsedAt ? Date.parse(t.lastUsedAt) : 0), {
      id: "lastUsed",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Last used" />,
      cell: ({ row }) => <Time iso={row.original.lastUsedAt} never="Not yet" />,
    }),
    // Never sorts after every date.
    col.accessor((t) => (t.expiresAt ? Date.parse(t.expiresAt) : Number.MAX_SAFE_INTEGER), {
      id: "expires",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Expires" />,
      cell: ({ row }) => <Expires token={row.original} />,
    }),
    // Every row a viewer sees is one they may revoke: admins see all rows,
    // members only their own. The server checks again.
    col.display({
      id: "actions",
      enableHiding: false,
      meta: { className: "w-24 text-right" },
      cell: ({ row }) => (
        <RevokeTokenButton token={row.original} isOwn={row.original.userId === currentUserId} />
      ),
    }),
  ]);
}

export function ApiTokensTable({
  tokens,
  isAdmin,
  currentUserId,
}: {
  tokens: ApiTokenRow[];
  isAdmin: boolean;
  currentUserId: string;
}) {
  return (
    <DataTable
      columns={columns(isAdmin, currentUserId)}
      data={tokens}
      getRowId={(t) => t.id}
      searchPlaceholder={isAdmin ? "Search tokens and users" : "Search tokens"}
      initialSorting={[{ id: "createdAt", desc: true }]}
    />
  );
}
