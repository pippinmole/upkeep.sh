"use client";

import Link from "next/link";

import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import { Badge } from "@/components/ui/badge";
import { KevBadge, SeverityBadge } from "@/components/vuln/badges";
import type { AgentStatus, HostListRow } from "@/lib/queries";
import { SEVERITIES } from "@/lib/severity";
import { formatDate, relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";

import { osLabel } from "../agents/agent-hosts";
import { HostRowActions } from "./host-row-actions";

export type HostState = "active" | "archived";

export const STATE_OPTIONS: { value: HostState; label: string }[] = [
  { value: "active", label: "Active" },
  { value: "archived", label: "Archived" },
];

const AGENT_DOT: Record<AgentStatus, string> = {
  online: "bg-emerald-500",
  stale: "bg-amber-500",
  never: "border border-dashed border-muted-foreground",
  revoked: "bg-muted-foreground/40",
};
const AGENT_STATUS_LABEL: Record<AgentStatus, string> = {
  online: "online",
  stale: "stale",
  never: "never connected",
  revoked: "revoked",
};

const time = (iso: string | null) => (iso ? Date.parse(iso) : 0);
const severityRank = (s: string | null) => {
  const i = SEVERITIES.indexOf(s as (typeof SEVERITIES)[number]);
  return i < 0 ? SEVERITIES.length : i;
};

const col = dataTableColumnHelper<HostListRow>();

export const hostColumns = col.columns([
  col.accessor((h) => h.label ?? h.hostname, {
    id: "host",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Host" />,
    enableHiding: false,
    cell: ({ row }) => {
      const h = row.original;
      return (
        <div className="flex flex-wrap items-center gap-1.5">
          <Link href={`/dashboard/hosts/${h.id}`} className="font-medium hover:underline">
            {h.label ?? h.hostname}
          </Link>
          {h.label && <span className="text-muted-foreground">{h.hostname}</span>}
          {h.duplicateOf && (
            <Link
              href={`/dashboard/hosts/${h.duplicateOf.id}`}
              title={`Same machine identity as ${h.duplicateOf.hostname}`}
            >
              <Badge
                variant="outline"
                className="border-amber-600/50 text-amber-800 dark:text-amber-200"
              >
                Possible duplicate
              </Badge>
            </Link>
          )}
          {h.mergedInto ? (
            <Link href={`/dashboard/hosts/${h.mergedInto.id}`}>
              <Badge variant="outline" className="text-muted-foreground">
                Merged into {h.mergedInto.hostname}
              </Badge>
            </Link>
          ) : (
            h.archivedAt && (
              <Badge variant="outline" className="text-muted-foreground">
                Archived
              </Badge>
            )
          )}
        </div>
      );
    },
  }),
  col.accessor((h) => osLabel(h), {
    id: "os",
    header: ({ column }) => <DataTableColumnHeader column={column} title="OS" />,
    cell: ({ getValue }) => (
      <span className="text-muted-foreground whitespace-nowrap">{getValue()}</span>
    ),
  }),
  col.accessor((h) => h.agents.map((a) => a.name).join(", "), {
    id: "agents",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Agents" />,
    cell: ({ row }) => {
      const agents = row.original.agents;
      if (agents.length === 0) return <span className="text-muted-foreground">None</span>;
      return (
        <div className="flex flex-col gap-0.5">
          {agents.map((a) => (
            <Link
              key={a.id}
              href="/dashboard/agents"
              className="inline-flex items-center gap-1.5 whitespace-nowrap hover:underline"
              title={`${a.name}: ${AGENT_STATUS_LABEL[a.status]}${a.mode !== "local" ? `, ${a.mode}` : ""}`}
            >
              <span className={cn("inline-block size-2 rounded-full", AGENT_DOT[a.status])} />
              <span className={cn(a.status === "revoked" && "text-muted-foreground line-through")}>
                {a.name}
              </span>
            </Link>
          ))}
        </div>
      );
    },
  }),
  col.accessor("openFindings", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Open findings" />,
    sortFn: (a, b) =>
      a.original.openFindings - b.original.openFindings ||
      severityRank(b.original.topSeverity) - severityRank(a.original.topSeverity),
    cell: ({ row }) => {
      const h = row.original;
      if (h.openFindings === 0) return <span className="text-muted-foreground">0</span>;
      const pills = (
        <span className="inline-flex flex-wrap items-center gap-1">
          <span className="mr-0.5 font-medium tabular-nums">{h.openFindings}</span>
          {h.topSeverity && <SeverityBadge severity={h.topSeverity} />}
          {h.kevVulns > 0 && <KevBadge count={h.kevVulns} />}
        </span>
      );
      return h.openVulns > 0 ? (
        <Link href={`/dashboard/hosts/${h.id}/vulnerabilities`} title="Open vulnerabilities">
          {pills}
        </Link>
      ) : (
        pills
      );
    },
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
    header: ({ column }) => <DataTableColumnHeader column={column} title="Added" />,
    sortFn: (a, b) => time(a.original.createdAt) - time(b.original.createdAt),
    cell: ({ row }) => (
      <span className="text-muted-foreground whitespace-nowrap">
        {formatDate(row.original.createdAt)}
      </span>
    ),
  }),
  // Facet-only column (hidden): Active / Archived.
  col.accessor((h): HostState => (h.archivedAt ? "archived" : "active"), {
    id: "state",
    header: "State",
    enableHiding: false,
    filterFn: "arrHas",
  }),
  col.display({
    id: "actions",
    enableHiding: false,
    cell: ({ row }) => (
      <div className="flex justify-end">
        <HostRowActions host={row.original} />
      </div>
    ),
  }),
]);
