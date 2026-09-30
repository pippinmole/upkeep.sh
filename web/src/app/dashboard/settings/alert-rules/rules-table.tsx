"use client";

import Link from "next/link";

import { ChannelIcon } from "@/components/brand/channel-icon";
import { DataTable } from "@/components/data-table/data-table";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import { ALERTS_URL, CHANNELS_URL } from "@/components/notifications/links";
import { EnabledBadge } from "@/components/notifications/shared";
import { Badge } from "@/components/ui/badge";
import { describeCondition } from "@/lib/alert-conditions";
import { durationLabel } from "@/lib/notifiers";
import type { AlertRuleRow } from "@/lib/queries-alerts";

import { RuleActions, type RuleCtx } from "./rule-actions";

function scopeText(r: AlertRuleRow, ctx: RuleCtx): string {
  if (!r.hostIds) return "All hosts";
  const names = r.hostIds.map((id) => {
    const h = ctx.hosts.find((h) => h.id === id);
    if (!h) return "deleted host";
    const n = h.label || h.hostname;
    return h.archived ? `${n} (archived)` : n;
  });
  return names.length <= 2 ? names.join(", ") : `${names.length} hosts`;
}

const col = dataTableColumnHelper<AlertRuleRow>();

function makeColumns(ctx: RuleCtx) {
  return col.columns([
    col.accessor("name", {
      header: ({ column }) => <DataTableColumnHeader column={column} title="Rule" />,
      enableHiding: false,
      cell: ({ row }) => (
        <span className="flex flex-wrap items-center gap-1.5 font-medium">
          {row.original.name}
          {row.original.isDefault && (
            <Badge variant="outline" className="font-normal">
              Default
            </Badge>
          )}
        </span>
      ),
    }),
    col.accessor((r) => describeCondition(r.condition), {
      id: "condition",
      header: "Condition",
      enableSorting: false,
      cell: ({ getValue }) => <span className="text-sm">{getValue()}</span>,
    }),
    col.accessor((r) => scopeText(r, ctx), {
      id: "scope",
      header: "Hosts",
      enableSorting: false,
      cell: ({ getValue }) => <span className="text-sm">{getValue()}</span>,
    }),
    col.accessor((r) => r.channels.map((c) => c.name).join(", "), {
      id: "channels",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Channels" />,
      cell: ({ getValue, row }) =>
        getValue() ? (
          <Link
            href={CHANNELS_URL}
            className="inline-flex max-w-64 items-center gap-1.5 hover:underline"
            title={getValue()}
          >
            {row.original.channels.slice(0, 3).map((c) => (
              <ChannelIcon
                key={c.id}
                type={c.type}
                className="text-muted-foreground size-4 shrink-0"
              />
            ))}
            <span className="truncate">{getValue()}</span>
          </Link>
        ) : (
          <span className="text-muted-foreground">Dashboard only</span>
        ),
    }),
    col.accessor(
      (r) => (r.digest ? `Digest, every ${durationLabel(r.digestIntervalSeconds)}` : "Immediate"),
      {
        id: "delivery",
        header: ({ column }) => <DataTableColumnHeader column={column} title="Delivery" />,
        cell: ({ getValue, row }) => (
          <span className="whitespace-nowrap">
            {getValue()}
            <span className="text-muted-foreground block text-xs">
              {row.original.notifyOnResolve ? "firing and resolved" : "firing only"}
            </span>
          </span>
        ),
      },
    ),
    col.accessor("firing", {
      header: ({ column }) => <DataTableColumnHeader column={column} title="Firing" />,
      cell: ({ row }) =>
        row.original.firing > 0 ? (
          <Link
            href={`${ALERTS_URL}?rule=${row.original.id}&state=firing`}
            className="font-medium text-amber-600 hover:underline dark:text-amber-400"
          >
            {row.original.firing}
          </Link>
        ) : (
          <span className="text-muted-foreground">0</span>
        ),
    }),
    col.accessor("enabled", {
      header: ({ column }) => <DataTableColumnHeader column={column} title="Status" />,
      cell: ({ row }) => <EnabledBadge enabled={row.original.enabled} />,
    }),
    col.display({
      id: "actions",
      enableHiding: false,
      cell: ({ row }) => <RuleActions rule={row.original} ctx={ctx} />,
    }),
  ]);
}

export function RulesTable({ rules, ...ctx }: { rules: AlertRuleRow[] } & RuleCtx) {
  return (
    <DataTable
      columns={makeColumns(ctx)}
      data={rules}
      getRowId={(r) => r.id}
      searchPlaceholder="Search rules"
      emptyMessage="No rules yet."
    />
  );
}
