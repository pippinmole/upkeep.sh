import { History } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { FilterBar } from "@/components/inventory/filter-bar";
import { Pager } from "@/components/inventory/pager";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { hostTitle, requireHost } from "@/lib/host-page";
import { getHostEcosystems, getHostPackages, type HostPackageRow } from "@/lib/queries-inventory";
import {
  filterParam,
  pageParam,
  param,
  parseAt,
  type SearchParams,
  withParams,
} from "@/lib/search-params";
import { formatDate, formatDateTime } from "@/lib/time";

const PAGE_SIZE = 50;

type Params = Promise<{ hostId: string }>;

export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  const { host } = await requireHost((await params).hostId);
  return { title: `Packages · ${hostTitle(host)}` };
}

// Column definitions. Adding a column (P1b: Status, Top severity, Fixed
// in) is one entry here plus the matching field on HostPackageRow; the
// table markup below doesn't change.
type Column = {
  key: string;
  header: string;
  className?: string;
  cell: (r: HostPackageRow) => React.ReactNode;
};

function columns(opts: { pointInTime: boolean }): Column[] {
  return [
    {
      key: "package",
      header: "Package",
      cell: (r) => (
        <div className="flex flex-col">
          <Link
            href={`/dashboard/packages/${encodeURIComponent(r.name)}`}
            className="font-medium hover:underline"
          >
            {r.name}
          </Link>
          {r.sourceName && r.sourceName !== r.name && (
            <span
              className="text-muted-foreground text-xs"
              title={
                r.sourceVersion && r.sourceVersion !== r.version
                  ? `Source ${r.sourceName} ${r.sourceVersion}`
                  : `Source ${r.sourceName}`
              }
            >
              src: {r.sourceName}
            </span>
          )}
        </div>
      ),
    },
    {
      key: "version",
      header: "Version",
      cell: (r) => <span className="font-mono text-xs">{r.version}</span>,
    },
    {
      key: "arch",
      header: "Arch",
      className: "text-muted-foreground",
      cell: (r) => r.arch || "—",
    },
    // P1b: { key: "status", header: "Status", ... }
    // P1b: { key: "severity", header: "Top severity", ... }
    // P1b: { key: "fixed", header: "Fixed in", ... }
    {
      key: "ecosystem",
      header: "Ecosystem",
      cell: (r) => (
        <Badge variant="outline" className="font-normal">
          {r.ecosystem}
        </Badge>
      ),
    },
    {
      key: "since",
      header: "Installed since",
      className: "text-muted-foreground whitespace-nowrap",
      cell: (r) => <span title={formatDateTime(r.firstSeenAt)}>{formatDate(r.firstSeenAt)}</span>,
    },
    ...(opts.pointInTime
      ? [
          {
            key: "removed",
            header: "Removed",
            className: "text-muted-foreground whitespace-nowrap",
            cell: (r: HostPackageRow) =>
              r.removedAt ? (
                <span title={formatDateTime(r.removedAt)}>{formatDate(r.removedAt)}</span>
              ) : (
                "still installed"
              ),
          },
        ]
      : []),
  ];
}

export default async function HostPackagesPage({
  params,
  searchParams,
}: {
  params: Params;
  searchParams: Promise<SearchParams>;
}) {
  const { hostId } = await params;
  const sp = await searchParams;
  const { userId, host } = await requireHost(hostId);

  const rawAt = param(sp, "at");
  const at = parseAt(rawAt);
  const filters = {
    q: param(sp, "q"),
    ecosystem: filterParam(sp, "ecosystem"),
    at,
    page: pageParam(sp),
    pageSize: PAGE_SIZE,
  };
  const [{ rows, total }, ecosystems] = await Promise.all([
    getHostPackages(userId, host.id, filters),
    getHostEcosystems(userId, host.id),
  ]);
  const cols = columns({ pointInTime: at !== null });
  const basePath = `/dashboard/hosts/${host.id}/packages`;
  const firstRecorded = host.inventory.length
    ? null
    : "No package inventory has been recorded for this host yet.";

  return (
    <div className="flex flex-col gap-3">
      <FilterBar
        action={basePath}
        q={filters.q}
        qPlaceholder="Filter by package or source…"
        ecosystem={{ value: filters.ecosystem, options: ecosystems }}
        at={{ value: at ? at.slice(0, 10) : null }}
      />

      {rawAt && !at && (
        <Alert variant="destructive">
          <AlertDescription>
            Ignoring invalid date “{rawAt}”. Use YYYY-MM-DD. Showing the current inventory.
          </AlertDescription>
        </Alert>
      )}
      {at && (
        <Alert>
          <History className="size-4" />
          <AlertDescription className="flex flex-wrap items-center justify-between gap-2">
            <span>
              Inventory as of <strong>{formatDateTime(at)}</strong>: packages installed at that
              moment, including ones removed since.
            </span>
            <Link
              href={`${basePath}${withParams(sp, { at: null, page: null })}`}
              className="font-medium underline-offset-4 hover:underline"
            >
              Show current
            </Link>
          </AlertDescription>
        </Alert>
      )}

      <div className="bg-card rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              {cols.map((c) => (
                <TableHead key={c.key}>{c.header}</TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={cols.length} className="text-muted-foreground h-24 text-center">
                  {firstRecorded ??
                    (at
                      ? "No packages were recorded as installed at that time."
                      : "No packages match these filters.")}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((r) => (
                <TableRow key={`${r.softwareId}:${r.firstSeenAt}`}>
                  {cols.map((c) => (
                    <TableCell key={c.key} className={c.className}>
                      {c.cell(r)}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
      <Pager
        basePath={basePath}
        searchParams={sp}
        page={filters.page}
        pageSize={PAGE_SIZE}
        total={total}
      />
    </div>
  );
}
