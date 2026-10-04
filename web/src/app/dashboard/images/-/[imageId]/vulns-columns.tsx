"use client";

import Link from "next/link";

import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import { hostName } from "@/components/docker-fleet/badges";
import { Badge } from "@/components/ui/badge";
import { FixCell, KevBadge, SeverityBadge } from "@/components/vuln/badges";
import { EpssValue } from "@/components/vuln/cve-facts";
import { AdvisoryLinks, vulnHref } from "@/components/vuln/links";
import { ImageOriginLine } from "@/components/vuln/where";
import type { ImageVulnRow } from "@/lib/queries-image-vulns";
import { formatDate, formatDateTime } from "@/lib/time";

// Vulnerabilities tab columns: one row per (source package, vuln_key), as
// findings group them. Sortable ids match VULNS_TABLE.sortKeys; severity,
// kev and fix carry the facets.

const col = dataTableColumnHelper<ImageVulnRow>();

function FindingsCell({ r }: { r: ImageVulnRow }) {
  if (r.findings.length === 0) {
    return (
      <span
        className="text-muted-foreground text-xs"
        title="No container on your hosts uses this image, so it has a score but no findings"
      >
        —
      </span>
    );
  }
  return (
    <ul className="flex flex-col gap-0.5 text-xs">
      {r.findings.map((f) => (
        <li key={f.hostId} className="whitespace-nowrap">
          <Link href={`/dashboard/hosts/${f.hostId}/containers`} className="hover:underline">
            {hostName(f)}
          </Link>{" "}
          {f.status === "open" ? (
            <span className="text-muted-foreground" title={formatDateTime(f.firstSeenAt)}>
              open since {formatDate(f.firstSeenAt)}
              {f.reopenedAt && ` · reopened ${formatDate(f.reopenedAt)}`}
            </span>
          ) : (
            <Badge variant="neutral" className="font-normal">
              resolved {formatDate(f.resolvedAt)}
            </Badge>
          )}
        </li>
      ))}
    </ul>
  );
}

export const vulnColumns = col.columns([
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
        <div className="flex flex-col items-start gap-0.5">
          <SeverityBadge severity={r.severity} />
          {r.distroSeverity && (
            <span className="text-muted-foreground text-xs whitespace-nowrap">
              {/* Language ecosystems store the GHSA's reviewed severity here. */}
              {r.ecosystem === "npm" || r.ecosystem === "pypi" || r.ecosystem === "golang"
                ? "advisory"
                : "distro"}
              : {r.distroSeverity}
            </span>
          )}
        </div>
      );
    },
  }),
  col.accessor((r) => (r.isKev ? "1" : ""), {
    id: "kev",
    header: ({ column }) => <DataTableColumnHeader column={column} title="KEV" />,
    enableSorting: false,
    cell: ({ row }) =>
      row.original.isKev ? <KevBadge /> : <span className="text-muted-foreground">—</span>,
  }),
  col.accessor("epssScore", {
    id: "epss",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="EPSS" className="-mr-3 ml-0" />
    ),
    meta: { className: "text-right tabular-nums" },
    cell: ({ getValue }) => {
      const v = getValue();
      return v === null ? (
        <span className="text-muted-foreground">—</span>
      ) : (
        <EpssValue score={v} className="text-xs" />
      );
    },
  }),
  col.accessor("cvssV3Score", {
    id: "cvss",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="CVSS" className="-mr-3 ml-0" />
    ),
    meta: { className: "text-right tabular-nums" },
    cell: ({ getValue }) => {
      const v = getValue();
      return <span className="text-xs tabular-nums">{v === null ? "—" : v.toFixed(1)}</span>;
    },
  }),
  col.accessor("sourcePackage", {
    id: "package",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Package" />,
    cell: ({ row }) => {
      const r = row.original;
      const others = r.packages.filter((p) => p !== r.sourcePackage);
      return (
        <div className="flex flex-col">
          <span className="font-medium">{r.sourcePackage}</span>
          {others.length > 0 && (
            <span
              className="text-muted-foreground line-clamp-2 max-w-56 text-xs whitespace-normal"
              title={r.packages.join(", ")}
            >
              {r.packages.join(", ")}
            </span>
          )}
          <ImageOriginLine origin={r} />
        </div>
      );
    },
  }),
  col.accessor("installedVersion", {
    id: "installed",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Installed" />,
    enableSorting: false,
    cell: ({ getValue }) => <span className="font-mono text-xs">{getValue()}</span>,
  }),
  col.accessor(
    (r) => (r.fixChannel === "standard" ? "available" : r.fixedVersion ? "pro" : "none"),
    {
      id: "fix",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Fixed in" />,
      enableSorting: false,
      cell: ({ row }) => {
        const r = row.original;
        return (
          <div className="flex flex-col items-start gap-1">
            <FixCell fixedVersion={r.fixedVersion} fixChannel={r.fixChannel} />
            {r.fixAdvisoryId && <AdvisoryLinks ids={[r.fixAdvisoryId]} />}
          </div>
        );
      },
    },
  ),
  col.display({
    id: "findings",
    header: "Findings",
    cell: ({ row }) => <FindingsCell r={row.original} />,
  }),
]);
