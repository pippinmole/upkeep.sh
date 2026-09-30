"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";

import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import { FixCell, KevBadge, ScoreLine, SeverityBadge } from "@/components/vuln/badges";
import { ImageFixCell, ImageWhereCell, KindBadge } from "@/components/vuln/where";
import type { FindingRow } from "@/lib/queries-vulns";
import { formatDate, formatDateTime } from "@/lib/time";

// Host Vulnerabilities tab columns: one row per finding, a host package
// (source package + binaries + installed version) or a package in an image
// a container on the host uses. Sortable ids match hostVulnsTable().sortKeys;
// kind (Where), severity, kev and fix carry the facets.

const col = dataTableColumnHelper<FindingRow & { hostId: string }>();

const dash = <span className="text-muted-foreground">—</span>;

// Opens the finding sheet (?v=), keeping the table's URL state.
function SheetLink({ vulnKey }: { vulnKey: string }) {
  const pathname = usePathname();
  const search = new URLSearchParams(useSearchParams().toString());
  search.set("v", vulnKey);
  return (
    <Link
      href={`${pathname}?${search.toString()}`}
      scroll={false}
      className="font-medium whitespace-nowrap hover:underline"
    >
      {vulnKey}
    </Link>
  );
}

export function hostVulnColumns(status: "open" | "resolved") {
  return col.columns([
    col.accessor("vulnKey", {
      id: "vuln",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Vulnerability" />,
      enableHiding: false,
      cell: ({ row }) => {
        const r = row.original;
        return (
          <div className="max-w-md">
            <SheetLink vulnKey={r.vulnKey} />
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
            <ScoreLine epss={r.epssScore} cvss={r.cvssV3Score} distroSeverity={r.distroSeverity} />
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
        return (
          <div className="flex flex-col items-start gap-1">
            {r.image ? (
              <ImageWhereCell image={r.image} vulnKey={r.vulnKey} hostId={r.hostId} />
            ) : (
              <KindBadge kind="package" />
            )}
            <PackageLine r={r} />
          </div>
        );
      },
    }),
    col.accessor(
      (r) => (r.fixChannel === "standard" ? "available" : r.requiresPro ? "pro" : "none"),
      {
        id: "fix",
        header: "Fix",
        enableSorting: false,
        cell: ({ row }) => {
          const r = row.original;
          return r.image ? (
            <ImageFixCell fixes={[r]} />
          ) : (
            <FixCell fixedVersion={r.fixedVersion} fixChannel={r.fixChannel} />
          );
        },
      },
    ),
    col.accessor((r) => (status === "resolved" ? r.resolvedAt : r.firstSeenAt), {
      id: "seen",
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title={status === "resolved" ? "Resolved" : "Detected"}
        />
      ),
      meta: { className: "text-muted-foreground whitespace-nowrap" },
      cell: ({ row, getValue }) => {
        const at = getValue();
        const r = row.original;
        return (
          <>
            {at ? <span title={formatDateTime(at)}>{formatDate(at)}</span> : dash}
            {r.reopenedAt && status === "open" && (
              <span className="block text-xs" title={formatDateTime(r.reopenedAt)}>
                reopened {formatDate(r.reopenedAt)}
              </span>
            )}
          </>
        );
      },
    }),
  ]);
}

// Source package, binaries and installed version: on the host, or inside
// the image.
function PackageLine({ r }: { r: FindingRow }) {
  const binaries =
    r.packages.length > 0 && !(r.packages.length === 1 && r.packages[0] === r.sourcePackage);
  return (
    <div className="flex flex-col">
      <span className={r.image ? "text-sm" : "font-medium"}>
        {r.image && <span className="text-muted-foreground">package </span>}
        {r.sourcePackage ?? "—"}{" "}
        <span className="text-muted-foreground font-mono text-xs">{r.installedVersion}</span>
      </span>
      {binaries && (
        <span
          className="text-muted-foreground line-clamp-2 max-w-56 text-xs whitespace-normal"
          title={r.packages.join(", ")}
        >
          {r.packages.join(", ")}
        </span>
      )}
      {r.runningKernelUnknown && (
        <span
          className="text-muted-foreground text-xs"
          title="The running kernel isn't known, so every installed kernel is counted"
        >
          kernel {r.kernelRelease ?? ""} · running kernel unknown
        </span>
      )}
    </div>
  );
}
