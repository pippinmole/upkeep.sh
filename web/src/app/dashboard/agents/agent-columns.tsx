"use client";

import { ChevronRight } from "lucide-react";

import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import { AGENT_STATUS_LABEL, agentStatusTone, StatusBadge } from "@/components/status";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { KevBadge, SeverityBadge } from "@/components/vuln/badges";
import type { AgentStatus, AgentWithHosts } from "@/lib/queries";
import { SEVERITIES } from "@/lib/severity";
import { cn } from "@/lib/utils";

import { NUMERIC_COLUMN, NUMERIC_HEADER, TimeAgo } from "../hosts/table-cells";
import { AgentRowActions } from "./agent-row-actions";

const STATUSES: AgentStatus[] = ["online", "stale", "never", "revoked"];
export const STATUS_OPTIONS = STATUSES.map((value) => ({
  value,
  label: AGENT_STATUS_LABEL[value],
}));
const STATUS_RANK = Object.fromEntries(STATUSES.map((s, i) => [s, i]));

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
        <span className="inline-flex flex-wrap items-center gap-1">
          <StatusBadge tone={agentStatusTone(s)} label={AGENT_STATUS_LABEL[s]} />
          {row.original.rotateRequestedAt && s !== "revoked" && (
            <Badge
              variant="dashed"
              className="whitespace-nowrap"
              title="Credential rotation requested; the agent rotates on its next push"
            >
              Rotation pending
            </Badge>
          )}
        </span>
      );
    },
  }),
  col.accessor((a) => a.hosts.length, {
    id: "hosts",
    meta: NUMERIC_COLUMN,
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Hosts" className={NUMERIC_HEADER} />
    ),
    cell: ({ row }) => row.original.hosts.length,
  }),
  col.accessor((a) => vulnSummary(a).open, {
    id: "vulnerabilities",
    meta: NUMERIC_COLUMN,
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Vulnerabilities" className={NUMERIC_HEADER} />
    ),
    cell: ({ row }) => {
      const v = vulnSummary(row.original);
      if (v.open === 0) return <span className="text-muted-foreground">0</span>;
      return (
        <span className="inline-flex flex-wrap items-center justify-end gap-1">
          {v.top && <SeverityBadge severity={v.top} />}
          {v.kev > 0 && <KevBadge count={v.kev} />}
          <span className="ml-0.5 font-medium">{v.open}</span>
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
    cell: ({ row }) => <TimeAgo iso={row.original.lastSeenAt} className="text-muted-foreground" />,
  }),
  col.accessor("createdAt", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Created" />,
    sortFn: (a, b) => time(a.original.createdAt) - time(b.original.createdAt),
    cell: ({ row }) => <TimeAgo iso={row.original.createdAt} className="text-muted-foreground" />,
  }),
  col.display({
    id: "actions",
    enableHiding: false,
    cell: ({ row }) => (
      <div className="flex justify-end">
        <AgentRowActions agent={row.original} />
      </div>
    ),
  }),
]);
