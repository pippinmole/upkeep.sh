"use client";

import Link from "next/link";

import { DataTable } from "@/components/data-table/data-table";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import { hostName } from "@/components/docker-fleet/badges";
import { Badge } from "@/components/ui/badge";
import { KevBadge, SeverityBadge } from "@/components/vuln/badges";
import { ImageFixCell, imageName, imageVulnHref } from "@/components/vuln/where";
import { platformLabel } from "@/lib/image-key";
import type { VulnImageRow } from "@/lib/queries-vulns";
import { formatDate, formatDateTime } from "@/lib/time";

// The CVE page's "Container images" table: one row per image key with a
// vulnerable_image finding for the CVE on the user's hosts (client-mode
// DataTable: a CVE is in a handful of images at most).

const col = dataTableColumnHelper<VulnImageRow & { vulnKey: string }>();

const columns = col.columns([
  col.accessor((r) => imageName(r.image), {
    id: "image",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Image" />,
    enableHiding: false,
    cell: ({ row }) => {
      const r = row.original;
      const more = r.image.refs.length - 1;
      return (
        <div className="flex max-w-64 flex-col items-start">
          <Link
            href={imageVulnHref(r.image, r.vulnKey)}
            className="font-medium break-all hover:underline"
            title={r.image.refs.join(", ") || r.image.imageId}
          >
            {imageName(r.image)}
          </Link>
          {more > 0 && (
            <span className="text-muted-foreground text-xs" title={r.image.refs.join(", ")}>
              +{more} more {more === 1 ? "tag" : "tags"}
            </span>
          )}
          {!r.open && (
            <Badge variant="success" className="mt-1">
              Resolved {formatDate(r.resolvedAt)}
            </Badge>
          )}
        </div>
      );
    },
  }),
  col.accessor((r) => platformLabel(r.image), {
    id: "platform",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Platform" />,
    meta: { className: "text-muted-foreground whitespace-nowrap" },
  }),
  col.accessor((r) => r.packages.map((p) => p.sourcePackage).join(", "), {
    id: "package",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Package" />,
    cell: ({ row }) => (
      <ul className="flex flex-col">
        {row.original.packages.map((p) => (
          <li key={p.sourcePackage}>
            <span className="font-medium">{p.sourcePackage ?? "—"}</span>{" "}
            <span className="text-muted-foreground font-mono text-xs">{p.installedVersion}</span>
          </li>
        ))}
      </ul>
    ),
  }),
  col.accessor("severity", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Severity" />,
    cell: ({ row }) => (
      <div className="flex flex-wrap gap-1">
        <SeverityBadge severity={row.original.severity} />
        {row.original.isKev && <KevBadge />}
      </div>
    ),
  }),
  col.accessor((r) => r.hosts.length, {
    id: "hosts",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Hosts and containers" />,
    cell: ({ row }) => (
      <ul className="flex flex-col gap-0.5 text-xs">
        {row.original.hosts.map((h) => (
          <li key={h.hostId}>
            <Link
              href={`/dashboard/hosts/${h.hostId}/vulnerabilities?kind=image&v=${encodeURIComponent(row.original.vulnKey)}${h.open ? "" : "&status=resolved"}`}
              className="font-medium hover:underline"
            >
              {hostName(h)}
            </Link>
            {h.containers.length > 0 && (
              <span className="text-muted-foreground"> · {h.containers.join(", ")}</span>
            )}
          </li>
        ))}
      </ul>
    ),
  }),
  col.display({
    id: "fix",
    header: "Fix",
    cell: ({ row }) => <ImageFixCell fixes={row.original.packages} />,
  }),
  col.accessor("firstSeenAt", {
    id: "since",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Since" />,
    meta: { className: "text-muted-foreground whitespace-nowrap" },
    cell: ({ getValue }) => (
      <span title={formatDateTime(getValue())}>{formatDate(getValue())}</span>
    ),
  }),
]);

export function VulnImagesTable({ rows, vulnKey }: { rows: VulnImageRow[]; vulnKey: string }) {
  return (
    <DataTable
      columns={columns}
      data={rows.map((r) => ({ ...r, vulnKey }))}
      getRowId={(r) => `${r.image.imageId}|${r.image.os}|${r.image.arch}|${r.image.variant}`}
      pageSize={20}
    />
  );
}
