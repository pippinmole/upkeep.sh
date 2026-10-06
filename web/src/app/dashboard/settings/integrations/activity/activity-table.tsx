"use client";

import { DataTable, type DataTableServerState } from "@/components/data-table/data-table";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import { useServerTable } from "@/components/data-table/url-state";
import { MCP_ACTIVITY_TABLE } from "@/lib/mcp-activity-table";
import type { McpActivityFacets, McpCallRow } from "@/lib/queries-mcp-activity";
import { formatDateTime, relativeTime } from "@/lib/time";

// MCP call log columns. Sortable ids match MCP_ACTIVITY_TABLE.sortKeys; the
// user (admins only), client and tool columns carry the facets.

const col = dataTableColumnHelper<McpCallRow>();

// Arguments on one line: `host=web-01 package=openssl`, or "none".
function argumentsText(args: unknown): string {
  if (!args || typeof args !== "object") return "";
  return Object.entries(args as Record<string, unknown>)
    .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
    .join(" ");
}

function columns(isAdmin: boolean, currentUserId: string) {
  return col.columns([
    col.accessor("createdAt", {
      id: "time",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Time" />,
      enableHiding: false,
      cell: ({ row }) => (
        <span className="whitespace-nowrap" title={formatDateTime(row.original.createdAt)}>
          {relativeTime(row.original.createdAt)}
        </span>
      ),
    }),
    ...(isAdmin
      ? [
          col.accessor((r) => r.username ?? r.email ?? "", {
            id: "user",
            header: "User",
            enableSorting: false,
            cell: ({ row }) => (
              <span className="whitespace-nowrap" title={row.original.email ?? undefined}>
                {row.original.username ?? row.original.email ?? (
                  <span className="text-muted-foreground">Deleted user</span>
                )}
                {row.original.userId === currentUserId && (
                  <span className="text-muted-foreground ml-1.5 text-xs">(you)</span>
                )}
              </span>
            ),
          }),
        ]
      : []),
    col.accessor((r) => r.clientName ?? "", {
      id: "client",
      header: "Client",
      enableSorting: false,
      cell: ({ row }) => (
        <div className="flex flex-col whitespace-nowrap">
          <span>{row.original.clientName ?? "Unnamed client"}</span>
          <span className="text-muted-foreground text-xs">
            {row.original.credentialKind === "oauth" ? "OAuth" : "API token"}
          </span>
        </div>
      ),
    }),
    col.accessor("tool", {
      header: ({ column }) => <DataTableColumnHeader column={column} title="Tool" />,
      cell: ({ row }) => <code className="text-xs whitespace-nowrap">{row.original.tool}</code>,
    }),
    col.accessor((r) => argumentsText(r.arguments), {
      id: "arguments",
      header: "Arguments",
      enableSorting: false,
      // Takes the space the others leave.
      meta: { className: "lg:w-full" },
      cell: ({ getValue }) => {
        const text = getValue();
        return text ? (
          <code className="block max-w-md truncate text-xs" title={text}>
            {text}
          </code>
        ) : (
          <span className="text-muted-foreground text-xs">none</span>
        );
      },
    }),
    col.accessor("resultItems", {
      id: "items",
      header: "Items",
      enableSorting: false,
      meta: { className: "text-right" },
      cell: ({ row }) => <span className="tabular-nums">{row.original.resultItems ?? "—"}</span>,
    }),
    col.accessor("durationMs", {
      id: "duration",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Duration" />,
      meta: { className: "text-right" },
      cell: ({ row }) => (
        <span className="whitespace-nowrap tabular-nums">{row.original.durationMs} ms</span>
      ),
    }),
    col.accessor((r) => r.error ?? "", {
      id: "error",
      header: "Result",
      enableSorting: false,
      cell: ({ row }) =>
        row.original.error ? (
          <span
            className="text-destructive block max-w-xs truncate text-sm"
            title={row.original.error}
          >
            {row.original.error}
          </span>
        ) : (
          <span className="text-muted-foreground text-sm">OK</span>
        ),
    }),
  ]);
}

export function ActivityTable({
  rows,
  total,
  state,
  facets,
  isAdmin,
  currentUserId,
}: {
  rows: McpCallRow[];
  total: number;
  state: DataTableServerState;
  facets: McpActivityFacets;
  isAdmin: boolean;
  currentUserId: string;
}) {
  const server = useServerTable(state, total, MCP_ACTIVITY_TABLE);
  return (
    <DataTable
      columns={columns(isAdmin, currentUserId)}
      data={rows}
      getRowId={(r) => r.id}
      server={server}
      searchPlaceholder="Search tools, clients, arguments, errors"
      facets={[
        ...(isAdmin
          ? [
              {
                columnId: "user",
                title: "User",
                options: facets.users.map((u) => ({
                  value: u.id,
                  label: `${u.name} (${u.count})`,
                })),
              },
            ]
          : []),
        {
          columnId: "client",
          title: "Client",
          options: facets.clients.map((c) => ({ value: c.id, label: `${c.name} (${c.count})` })),
        },
        {
          columnId: "tool",
          title: "Tool",
          options: facets.tools.map((t) => ({ value: t.name, label: `${t.name} (${t.count})` })),
        },
      ]}
      emptyMessage="No calls match these filters."
    />
  );
}
