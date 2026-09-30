"use client";

import Link from "next/link";

import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import { StatusBadge } from "@/components/status";
import { ALERT_STATE_LABEL, RESOLVED_REASON_LABEL } from "@/lib/alerts-table";
import type { AlertRow } from "@/lib/queries-alerts";
import { formatDateTime, relativeTime } from "@/lib/time";

// Alerts list columns. Sortable ids match ALERTS_TABLE.sortKeys; the
// state, rule and host columns carry the facets (?state=, ?rule=, ?host=).

const col = dataTableColumnHelper<AlertRow>();

// A short line of the details that matter per property.
function detailText(r: AlertRow): string | null {
  const d = r.details;
  const list = (v: unknown) => (Array.isArray(v) ? v.join(", ") : null);
  switch (r.property) {
    case "listening_port": {
      const addrs = list(d.addresses);
      const procs = list(d.processes);
      return [addrs && `on ${addrs}`, procs && `(${procs})`].filter(Boolean).join(" ") || null;
    }
    case "package_installed":
      return list(d.versions) ? `version ${list(d.versions)}` : null;
    case "collector_failed":
      return typeof d.error === "string" ? d.error : null;
    case "reboot_required":
      return list(d.packages);
    case "host_not_seen":
      return typeof d.last_seen_at === "string"
        ? `last seen ${relativeTime(d.last_seen_at)}`
        : null;
    default:
      return null;
  }
}

function duration(from: string, to: string | null): string {
  const ms = new Date(to ?? Date.now()).getTime() - new Date(from).getTime();
  const m = Math.max(0, Math.round(ms / 60000));
  if (m < 60) return `${m}m`;
  if (m < 1440) return `${Math.floor(m / 60)}h ${m % 60}m`;
  return `${Math.floor(m / 1440)}d ${Math.floor((m % 1440) / 60)}h`;
}

export const alertColumns = col.columns([
  col.accessor("state", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="State" />,
    enableHiding: false,
    cell: ({ row }) => (
      <StatusBadge
        tone={row.original.state === "firing" ? "warning" : "success"}
        label={ALERT_STATE_LABEL[row.original.state]}
      />
    ),
  }),
  col.accessor("title", {
    header: "Alert",
    enableSorting: false,
    enableHiding: false,
    cell: ({ row }) => {
      const r = row.original;
      const detail = detailText(r);
      return (
        <div className="flex max-w-md min-w-0 flex-col">
          <span className="font-medium">{r.title}</span>
          {detail && (
            <span className="text-muted-foreground truncate text-xs" title={detail}>
              {detail}
            </span>
          )}
        </div>
      );
    },
  }),
  col.accessor("hostName", {
    id: "host",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Host" />,
    cell: ({ row }) => (
      <Link href={`/dashboard/hosts/${row.original.hostId}`} className="hover:underline">
        {row.original.hostName}
      </Link>
    ),
  }),
  col.accessor("ruleName", {
    id: "rule",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Rule" />,
    cell: ({ row }) => (
      <span className={row.original.ruleId ? "" : "text-muted-foreground"}>
        {row.original.ruleName}
        {!row.original.ruleId && " (deleted)"}
      </span>
    ),
  }),
  col.accessor("firedAt", {
    id: "fired",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Fired" />,
    cell: ({ row }) => (
      <span className="whitespace-nowrap" title={formatDateTime(row.original.firedAt)}>
        {relativeTime(row.original.firedAt)}
      </span>
    ),
  }),
  col.accessor("resolvedAt", {
    id: "resolved",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Resolved" />,
    cell: ({ row }) => {
      const r = row.original;
      if (!r.resolvedAt) {
        return (
          <span className="text-muted-foreground whitespace-nowrap text-xs">
            firing for {duration(r.firedAt, null)}
          </span>
        );
      }
      return (
        <div className="flex flex-col whitespace-nowrap">
          <span title={formatDateTime(r.resolvedAt)}>{relativeTime(r.resolvedAt)}</span>
          <span className="text-muted-foreground text-xs">
            {RESOLVED_REASON_LABEL[r.resolvedReason ?? ""] ?? r.resolvedReason} · after{" "}
            {duration(r.firedAt, r.resolvedAt)}
          </span>
        </div>
      );
    },
  }),
]);
