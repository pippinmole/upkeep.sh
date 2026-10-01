"use client";

import Link from "next/link";

import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import {
  KevBadge,
  NoFixBadge,
  ProFixBadge,
  ScoreLine,
  SeverityBadge,
} from "@/components/vuln/badges";
import { vulnHref } from "@/components/vuln/links";
import { ImageFixCell, ImageWhereCell, KindBadge } from "@/components/vuln/where";
import type { FleetVulnRow } from "@/lib/queries-vuln-list";
import { formatDate, formatDateTime } from "@/lib/time";

// Fleet Vulnerabilities columns: one row per (vuln_key, host packages) and
// per (vuln_key, image key). Sortable ids match FLEET_VULN_SORTS;
// kind (Where), severity, kev and fix carry the facets.

const col = dataTableColumnHelper<FleetVulnRow>();

const dash = <span className="text-muted-foreground">—</span>;

export function fleetColumns(status: "open" | "resolved") {
  const resolved = status === "resolved";
  return col.columns([
    col.accessor("vulnKey", {
      id: "vuln",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Vulnerability" />,
      enableHiding: false,
      cell: ({ row }) => {
        const r = row.original;
        return (
          <div className="max-w-md">
            <Link
              href={vulnHref(r.vulnKey)}
              className="font-medium whitespace-nowrap hover:underline"
            >
              {r.vulnKey}
            </Link>
            {r.description && (
              <p
                className="text-muted-foreground line-clamp-2 text-xs whitespace-normal"
                title={r.description}
              >
                {r.description}
              </p>
            )}
          </div>
        );
      },
    }),
    col.accessor("severity", {
      header: ({ column }) => <DataTableColumnHeader column={column} title="Severity" />,
      cell: ({ row }) => {
        const r = row.original;
        return (
          <div className="flex flex-col items-start gap-1">
            <SeverityBadge severity={r.severity} />
            <ScoreLine epss={r.epssScore} cvss={r.cvssV3Score} distroSeverity={null} />
          </div>
        );
      },
    }),
    col.accessor((r) => (r.isKev ? "1" : ""), {
      id: "kev",
      header: ({ column }) => <DataTableColumnHeader column={column} title="KEV" />,
      enableSorting: false,
      cell: ({ row }) => (row.original.isKev ? <KevBadge /> : dash),
    }),
    col.accessor("kind", {
      header: "Where",
      enableSorting: false,
      cell: ({ row }) => {
        const r = row.original;
        if (r.image) return <ImageWhereCell image={r.image} vulnKey={r.vulnKey} />;
        return (
          <div className="flex flex-col items-start gap-0.5">
            <KindBadge kind="package" />
            <span
              className="line-clamp-2 max-w-56 text-sm whitespace-normal"
              title={r.packages.join(", ") || undefined}
            >
              {r.packages.join(", ") || "—"}
            </span>
          </div>
        );
      },
    }),
    col.accessor(status === "open" ? "affectedHosts" : "previousHosts", {
      id: "hosts",
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title={resolved ? "Hosts affected" : "Affected hosts"}
          className="-mr-3 ml-0"
        />
      ),
      meta: { className: "text-right tabular-nums" },
      cell: ({ row }) => {
        const r = row.original;
        if (resolved) {
          return (
            <span title="Hosts this was found on before it was resolved">{r.previousHosts}</span>
          );
        }
        return (
          <>
            {r.affectedHosts}
            {r.previousHosts > 0 && (
              <span
                className="text-muted-foreground block text-xs"
                title="Hosts where this vulnerability was found and has since been resolved"
              >
                +{r.previousHosts} {r.previousHosts === 1 ? "host" : "hosts"} resolved
              </span>
            )}
          </>
        );
      },
    }),
    // Resolved rows have no Fix column: their fix data is from when they
    // were open, and resolved can also mean removed.
    ...(resolved ? [] : [fixColumn]),
    col.accessor((r) => (resolved ? r.resolvedAt : r.firstSeenAt), {
      id: "seen",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={resolved ? "Resolved" : "First seen"} />
      ),
      meta: { className: "text-muted-foreground whitespace-nowrap" },
      cell: ({ getValue }) => {
        const at = getValue();
        return at ? <span title={formatDateTime(at)}>{formatDate(at)}</span> : dash;
      },
    }),
  ]);
}

const fixColumn = col.accessor((r) => (r.anyFix ? "available" : r.proOnly ? "pro" : "none"), {
  id: "fix",
  header: "Fix",
  enableSorting: false,
  cell: ({ row }) => {
    const r = row.original;
    if (r.image) return <ImageFixCell fixes={r.imageFixes} />;
    return (
      <div className="flex flex-col items-start gap-1">
        {r.anyFix && <span className="text-sm">Upgrade available</span>}
        {r.proOnly && <ProFixBadge />}
        {r.noFix && <NoFixBadge />}
      </div>
    );
  },
});
