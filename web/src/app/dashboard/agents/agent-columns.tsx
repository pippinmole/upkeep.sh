"use client";

import { ChevronRight } from "lucide-react";

import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { KevBadge, SeverityBadge } from "@/components/vuln/badges";
import type { AgentStatus, AgentWithHosts } from "@/lib/queries";
import { SEVERITIES } from "@/lib/severity";
import { formatDate, relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";

export const STATUS_OPTIONS: { value: AgentStatus; label: string }[] = [
  { value: "online", label: "Online" },
  { value: "stale", label: "Stale" },
  { value: "never", label: "Never connected" },
  { value: "revoked", label: "Revoked" },
];
const STATUS_RANK = Object.fromEntries(STATUS_OPTIONS.map((o, i) => [o.value, i]));
const STATUS_CLASS: Record<AgentStatus, string> = {
  online: "border-emerald-600/40 bg-emerald-500/10 text-emerald-800 dark:text-emerald-200",
  stale: "border-amber-600/40 bg-amber-400/15 text-amber-900 dark:text-amber-200",
  never: "border-dashed text-muted-foreground",
  revoked: "bg-muted text-muted-foreground",
};

const time = (iso: string | null) => (iso ? Date.parse(iso) : 0);
const dash = (v: string | null) => v ?? "—";

// Vuln totals across the agent's hosts (most urgent severity wins).
function vulnSummary(a: AgentWithHosts) {
  let open = 0;
  let kev = 0;
  let top: number | null = null;
  for (const h of a.hosts) {
    open += h.openVulns;
    kev += h.kevVulns;
    const i = SEVERITIES.indexOf(h.topVulnSeverity as (typeof SEVERITIES)[number]);
    if (i >= 0 && (top === null || i < top)) top = i;
  }
  return { open, kev, top: top === null ? null : SEVERITIES[top] };
}

const col = dataTableColumnHelper<AgentWithHosts>();

export const agentColumns = col.columns([
  col.display({
    id: "expand",
    enableHiding: false,
    cell: ({ row }) => (
      <Button
        variant="ghost"
        size="icon"
        className="size-7"
        onClick={row.getToggleExpandedHandler()}
        aria-expanded={row.getIsExpanded()}
        aria-label={row.getIsExpanded() ? "Hide hosts" : "Show hosts"}
      >
        <ChevronRight
          className={cn("size-4 transition-transform", row.getIsExpanded() && "rotate-90")}
        />
      </Button>
    ),
  }),
  col.accessor("name", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Agent" />,
    enableHiding: false,
    cell: ({ row }) => <span className="font-medium">{row.original.name}</span>,
  }),
  col.accessor("status", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Status" />,
    filterFn: "arrHas",
    sortFn: (a, b) => STATUS_RANK[a.original.status] - STATUS_RANK[b.original.status],
    cell: ({ row }) => {
      const s = row.original.status;
      return (
        <Badge variant="outline" className={cn("whitespace-nowrap", STATUS_CLASS[s])}>
          {STATUS_OPTIONS.find((o) => o.value === s)?.label}
        </Badge>
      );
    },
  }),
  col.accessor((a) => a.hosts.length, {
    id: "hosts",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Hosts" />,
    cell: ({ row }) => <span className="tabular-nums">{row.original.hosts.length}</span>,
  }),
  col.accessor((a) => vulnSummary(a).open, {
    id: "vulnerabilities",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Vulnerabilities" />,
    cell: ({ row }) => {
      const v = vulnSummary(row.original);
      if (v.open === 0) return <span className="text-muted-foreground">0</span>;
      return (
        <span className="inline-flex flex-wrap items-center gap-1">
          <span className="mr-0.5 font-medium tabular-nums">{v.open}</span>
          {v.top && <SeverityBadge severity={v.top} />}
          {v.kev > 0 && <KevBadge count={v.kev} />}
        </span>
      );
    },
  }),
  col.accessor("agentVersion", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Version" />,
    cell: ({ row }) => <span className="font-mono text-xs">{dash(row.original.agentVersion)}</span>,
  }),
  col.accessor("platform", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Platform" />,
    cell: ({ row }) => <span className="font-mono text-xs">{dash(row.original.platform)}</span>,
  }),
  col.accessor("lastSeenAt", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Last seen" />,
    sortFn: (a, b) => time(a.original.lastSeenAt) - time(b.original.lastSeenAt),
    cell: ({ row }) => (
      <span className="text-muted-foreground whitespace-nowrap">
        {relativeTime(row.original.lastSeenAt)}
      </span>
    ),
  }),
  col.accessor("createdAt", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Created" />,
    sortFn: (a, b) => time(a.original.createdAt) - time(b.original.createdAt),
    cell: ({ row }) => (
      <span className="text-muted-foreground whitespace-nowrap">
        {formatDate(row.original.createdAt)}
      </span>
    ),
  }),
]);
