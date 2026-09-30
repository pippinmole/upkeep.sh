"use client";

import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import { EcosystemIcon } from "@/components/brand";
import { Badge } from "@/components/ui/badge";
import { KevBadge, SeverityBadge } from "@/components/vuln/badges";
import { isAssessedDistro } from "@/lib/assessed";
import { IMAGE_PACKAGE_STATUS_LABEL } from "@/lib/image-tables";
import type { ImagePackageRow } from "@/lib/queries-image-packages";

// Packages tab columns. Sortable ids match PACKAGES_TABLE.sortKeys; the
// ecosystem and status columns carry the facets (?ecosystem=, ?status=).

const col = dataTableColumnHelper<ImagePackageRow>();

const MAX_PATHS = 2;

function notAssessedTitle(r: ImagePackageRow): string {
  if (r.distro && r.releaseSupported === false)
    return `${r.distro} ${r.release} is out of support: its advisories aren't imported`;
  if (r.distro && r.release === "") return "Distro package without a release: can't be matched";
  if (r.distro && isAssessedDistro(r.distro) && r.releaseSupported === null)
    return `${r.distro} ${r.release} isn't a release the matcher knows: its advisories aren't imported`;
  return `The matcher doesn't cover ${r.ecosystem}${r.distro ? ` (${r.distro})` : ""} packages yet`;
}

function StatusCell({ r }: { r: ImagePackageRow }) {
  switch (r.status) {
    case "vulnerable": {
      const details = [
        r.unfixed > 0 && `${r.unfixed} no fix yet`,
        r.fixable > 0 && `${r.fixable} fixable`,
      ].filter(Boolean);
      return (
        <div className="flex flex-col items-start gap-0.5">
          <div className="flex flex-wrap items-center gap-1">
            <SeverityBadge severity={r.worst} />
            {r.kev > 0 && <KevBadge count={r.kev > 1 ? r.kev : undefined} />}
            <span className="text-xs font-medium whitespace-nowrap">
              {r.vulns} {r.vulns === 1 ? "vuln" : "vulns"}
            </span>
          </div>
          {details.length > 0 && (
            <span className="text-muted-foreground text-xs whitespace-nowrap">
              {details.join(" · ")}
            </span>
          )}
        </div>
      );
    }
    case "not-assessed":
      return (
        <Badge
          variant="dashed"
          className="cursor-help font-normal whitespace-nowrap"
          title={notAssessedTitle(r)}
        >
          Not assessed
        </Badge>
      );
    case "pending":
      return (
        <span className="text-muted-foreground text-xs" title="Queued for the matcher">
          {IMAGE_PACKAGE_STATUS_LABEL.pending}
        </span>
      );
    default:
      return <span className="text-muted-foreground text-xs">None known</span>;
  }
}

export const packageColumns = col.columns([
  col.accessor("name", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Package" />,
    enableHiding: false,
    cell: ({ row }) => {
      const r = row.original;
      return (
        <div className="flex max-w-72 min-w-0 flex-col">
          <span className="truncate font-medium" title={r.name}>
            {r.name}
          </span>
          {r.arch && <span className="text-muted-foreground text-xs">{r.arch}</span>}
        </div>
      );
    },
  }),
  col.accessor("version", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Version" />,
    enableSorting: false,
    cell: ({ getValue }) => (
      <span className="block max-w-48 truncate font-mono text-xs" title={getValue()}>
        {getValue()}
      </span>
    ),
  }),
  col.accessor("ecosystem", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Ecosystem" />,
    cell: ({ row }) => {
      const r = row.original;
      return (
        <div className="flex flex-col items-start gap-0.5">
          <Badge variant="outline" className="font-normal">
            <EcosystemIcon ecosystem={r.ecosystem} />
            {r.ecosystem}
          </Badge>
          {r.distro && (
            <span className="text-muted-foreground text-xs whitespace-nowrap">
              {r.distro}
              {r.release && ` ${r.release}`}
            </span>
          )}
        </div>
      );
    },
  }),
  col.accessor((r) => r.sourceName ?? "", {
    id: "source",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Source package" />,
    enableSorting: false,
    cell: ({ row }) => {
      const r = row.original;
      if (!r.sourceName || (r.sourceName === r.name && r.sourceVersion === r.version))
        return <span className="text-muted-foreground">—</span>;
      return (
        <div className="flex flex-col">
          <span className="text-sm">{r.sourceName}</span>
          {r.sourceVersion && r.sourceVersion !== r.version && (
            <span className="text-muted-foreground font-mono text-xs">{r.sourceVersion}</span>
          )}
        </div>
      );
    },
  }),
  col.accessor((r) => r.paths.join("\n"), {
    id: "paths",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Found at" />,
    enableSorting: false,
    cell: ({ row }) => {
      const paths = row.original.paths;
      if (paths.length === 0) return <span className="text-muted-foreground">—</span>;
      return (
        <div
          className="flex max-w-72 flex-col font-mono text-xs"
          title={paths.length > MAX_PATHS ? paths.join("\n") : undefined}
        >
          {paths.slice(0, MAX_PATHS).map((p) => (
            <span key={p} className="truncate" title={p}>
              {p}
            </span>
          ))}
          {paths.length > MAX_PATHS && (
            <span className="text-muted-foreground font-sans">
              +{paths.length - MAX_PATHS} more
            </span>
          )}
        </div>
      );
    },
  }),
  col.accessor("status", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Vulnerabilities" />,
    cell: ({ row }) => <StatusCell r={row.original} />,
  }),
]);
