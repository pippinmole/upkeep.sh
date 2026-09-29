"use client";

import { RotateCw } from "lucide-react";
import Link from "next/link";

import { OsLogo } from "@/components/brand";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import { AGENT_STATUS_LABEL, agentStatusTone, StatusDot } from "@/components/status";
import { Badge } from "@/components/ui/badge";
import { KevBadge, SeverityBadge } from "@/components/vuln/badges";
import type { HostListRow } from "@/lib/queries";
import { osLabel } from "@/lib/os";
import { SEVERITIES } from "@/lib/severity";
import { cn } from "@/lib/utils";

import { HostRowActions } from "./host-row-actions";
import { RemoteTargetBadge } from "./remote-target-dialog";
import { NUMERIC_COLUMN, NUMERIC_HEADER, TimeAgo } from "./table-cells";

export type HostState = "active" | "archived";

export const STATE_OPTIONS: { value: HostState; label: string }[] = [
  { value: "active", label: "Active" },
  { value: "archived", label: "Archived" },
];

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
          <OsLogo osId={h.osId} size={16} className="text-muted-foreground" />
          <Link href={`/dashboard/hosts/${h.id}`} className="font-medium hover:underline">
            {h.label ?? h.hostname}
          </Link>
          {h.label && <span className="text-muted-foreground">{h.hostname}</span>}
          {h.rebootRequired && !h.archivedAt && (
            <Badge variant="warning" title="The latest snapshot reports a pending reboot">
              <RotateCw aria-hidden />
              Reboot required
            </Badge>
          )}
          {h.duplicateOf && (
            <Link
              href={`/dashboard/hosts/${h.duplicateOf.id}`}
              title={`Same machine identity as ${h.duplicateOf.hostname}`}
            >
              <Badge variant="warning">Possible duplicate</Badge>
            </Link>
          )}
          {h.mergedInto ? (
            <Link href={`/dashboard/hosts/${h.mergedInto.id}`}>
              <Badge variant="neutral">Merged into {h.mergedInto.hostname}</Badge>
            </Link>
          ) : (
            h.archivedAt && <Badge variant="neutral">Archived</Badge>
          )}
        </div>
      );
    },
  }),
  col.accessor((h) => osLabel(h.osId, h.osVersion) ?? "", {
    id: "os",
    header: ({ column }) => <DataTableColumnHeader column={column} title="OS" />,
    cell: ({ row, getValue }) => (
      <span
        className="text-muted-foreground whitespace-nowrap"
        title={row.original.osCodename ?? undefined}
      >
        {getValue() || "—"}
      </span>
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
            <span key={a.id} className="inline-flex flex-wrap items-center gap-1.5">
              <Link
                href="/dashboard/agents"
                className="inline-flex items-center gap-1.5 whitespace-nowrap hover:underline"
                title={`${a.name}: ${AGENT_STATUS_LABEL[a.status]}${a.mode !== "local" ? `, ${a.mode}` : ""}`}
              >
                <StatusDot tone={agentStatusTone(a.status)} label={AGENT_STATUS_LABEL[a.status]} />
                <span
                  className={cn(a.status === "revoked" && "text-muted-foreground line-through")}
                >
                  {a.name}
                </span>
                {a.mode !== "local" && <span className="text-muted-foreground">via {a.mode}</span>}
                {/* Online is the normal case; any other state is also spelled out
                    (the dot's sr-only label already names it for screen readers). */}
                {a.status !== "online" && (
                  <span aria-hidden className="text-muted-foreground">
                    · {AGENT_STATUS_LABEL[a.status]}
                  </span>
                )}
              </Link>
              <RemoteTargetBadge agent={a} hostId={row.original.id} />
            </span>
          ))}
        </div>
      );
    },
  }),
  col.accessor("openFindings", {
    meta: NUMERIC_COLUMN,
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Open findings" className={NUMERIC_HEADER} />
    ),
    sortFn: (a, b) =>
      a.original.openFindings - b.original.openFindings ||
      severityRank(b.original.topSeverity) - severityRank(a.original.topSeverity),
    cell: ({ row }) => {
      const h = row.original;
      if (h.openFindings === 0) return <span className="text-muted-foreground">0</span>;
      const pills = (
        <span className="inline-flex flex-wrap items-center justify-end gap-1">
          {h.topSeverity && <SeverityBadge severity={h.topSeverity} />}
          {h.kevVulns > 0 && <KevBadge count={h.kevVulns} />}
          <span className="ml-0.5 font-medium tabular-nums">{h.openFindings}</span>
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
    cell: ({ row }) => <TimeAgo iso={row.original.lastSeenAt} className="text-muted-foreground" />,
  }),
  col.accessor("createdAt", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Added" />,
    sortFn: (a, b) => time(a.original.createdAt) - time(b.original.createdAt),
    cell: ({ row }) => <TimeAgo iso={row.original.createdAt} className="text-muted-foreground" />,
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
