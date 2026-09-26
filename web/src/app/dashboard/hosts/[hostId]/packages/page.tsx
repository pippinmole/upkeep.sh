import { History, Info } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

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
import { FixCell, KevBadge, ScoreLine, SeverityBadge } from "@/components/vuln/badges";
import { AdvisoryLinks, vulnHref } from "@/components/vuln/links";
import { UrlSheet } from "@/components/vuln/url-sheet";
import { hostTitle, requireHost } from "@/lib/host-page";
import {
  getHostEcosystems,
  getHostPackages,
  type HostPackageRow,
  type PackageStatusFilter,
} from "@/lib/queries-inventory";
import { getPackageVulns, type PackageVulnSheet } from "@/lib/queries-vulns";
import {
  filterParam,
  oneOf,
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

// Column definitions. Adding a column is one entry here plus the matching
// field on HostPackageRow; the table markup below doesn't change.
type Column = {
  key: string;
  header: string;
  className?: string;
  cell: (r: HostPackageRow) => React.ReactNode;
};

function columns(opts: {
  pointInTime: boolean;
  runningKernel: string | null;
  sheetHref: (softwareId: string) => string;
}): Column[] {
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
    {
      key: "status",
      header: "Status",
      cell: (r) => (
        <StatusCell
          r={r}
          pointInTime={opts.pointInTime}
          runningKernel={opts.runningKernel}
          href={opts.sheetHref}
        />
      ),
    },
    {
      key: "severity",
      header: "Top severity",
      cell: (r) =>
        r.vuln.open > 0 ? (
          <div className="flex flex-wrap gap-1">
            <SeverityBadge severity={r.vuln.topSeverity} />
            {r.vuln.kev > 0 && <KevBadge count={r.vuln.kev > 1 ? r.vuln.kev : undefined} />}
          </div>
        ) : opts.pointInTime && r.known.kev > 0 ? (
          <KevBadge count={r.known.kev > 1 ? r.known.kev : undefined} />
        ) : null,
    },
    {
      key: "fixed",
      header: "Fixed in",
      cell: (r) =>
        r.vuln.open > 0 || r.known.total > 0 ? (
          r.maxFixedVersion ? (
            <span
              className="font-mono text-xs"
              title="Highest fixed version in the standard archive across this package's vulnerabilities: upgrading to it fixes every fixable one"
            >
              {r.maxFixedVersion}
            </span>
          ) : (
            <span className="text-muted-foreground text-xs">no standard fix</span>
          )
        ) : null,
    },
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
    status: oneOf<PackageStatusFilter>(sp, "status", ["vulnerable", "kev", "no-fix"]),
    sort: oneOf(sp, "sort", ["severity", "name"] as const) ?? "severity",
    page: pageParam(sp),
    pageSize: PAGE_SIZE,
  };
  const pkgParam = param(sp, "pkg");
  const [{ rows, total }, ecosystems, sheet] = await Promise.all([
    getHostPackages(userId, host.id, filters),
    getHostEcosystems(userId, host.id),
    pkgParam ? getPackageVulns(userId, host.id, pkgParam) : null,
  ]);
  // ?pkg= for a version this host never had (or another user's) is a 404.
  if (pkgParam && !sheet) notFound();
  const basePath = `/dashboard/hosts/${host.id}/packages`;
  const cols = columns({
    pointInTime: at !== null,
    runningKernel: host.runningKernel,
    sheetHref: (id) => `${basePath}${withParams(sp, { pkg: id })}`,
  });
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
        selects={[
          {
            name: "status",
            label: "Vulnerability status",
            value: filters.status,
            allLabel: "All packages",
            options: [
              { value: "vulnerable", label: "Vulnerable only" },
              { value: "kev", label: "Known exploited" },
              { value: "no-fix", label: "With unfixed vulns" },
            ],
            className: "w-44",
          },
        ]}
        sort={{
          value: filters.sort,
          options: [
            { value: "severity", label: "Most urgent first" },
            { value: "name", label: "Name" },
          ],
        }}
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
              moment, including ones removed since. Vulnerability counts are those versions matched
              against today&apos;s advisories.
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
                    (filters.status
                      ? "No packages match this vulnerability filter."
                      : at
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
      {sheet && (
        <PackageSheet
          sheet={sheet}
          closeHref={`${basePath}${withParams(sp, { pkg: null })}`}
          runningKernel={host.runningKernel}
        />
      )}
    </div>
  );
}

// A kernel package that is known not to be the running kernel: its
// matches are informational (no findings). False while the running kernel
// is unknown, since findings then cover every installed kernel.
function isOtherKernel(kernelRelease: string | null, runningKernel: string | null): boolean {
  return kernelRelease !== null && runningKernel !== null && kernelRelease !== runningKernel;
}

function StatusCell({
  r,
  pointInTime,
  runningKernel,
  href,
}: {
  r: HostPackageRow;
  pointInTime: boolean;
  runningKernel: string | null;
  href: (softwareId: string) => string;
}) {
  const link = (children: React.ReactNode, title?: string) => (
    <Link href={href(r.softwareId)} scroll={false} title={title} className="hover:underline">
      {children}
    </Link>
  );
  if (!pointInTime && r.vuln.open > 0) {
    const details = [
      r.vuln.unfixed > 0 && `${r.vuln.unfixed} no fix yet`,
      r.vuln.proOnly > 0 && `${r.vuln.proOnly} fix requires Pro`,
    ].filter(Boolean);
    return (
      <div className="flex flex-col">
        {link(<span className="font-medium whitespace-nowrap">Vulnerable ({r.vuln.open})</span>)}
        {details.length > 0 && (
          <span className="text-muted-foreground text-xs whitespace-nowrap">
            {details.join(" · ")}
          </span>
        )}
      </div>
    );
  }
  if (r.known.total > 0) {
    // Point-in-time: today's matches for that version. Current view with
    // matches but no open finding: a kernel that isn't the running one
    // (Q7), or a finding not reconciled yet.
    const otherKernel = isOtherKernel(r.kernelRelease, runningKernel);
    const label = pointInTime
      ? `${r.known.total} known ${r.known.total === 1 ? "vulnerability" : "vulnerabilities"}`
      : otherKernel
        ? `Not the running kernel (${r.known.total})`
        : `${r.known.total} matched, no open finding`;
    return link(
      <span className="text-muted-foreground text-xs whitespace-nowrap">{label}</span>,
      otherKernel && !pointInTime
        ? "Informational: kernel vulnerabilities are raised only for the running kernel"
        : undefined,
    );
  }
  return <span className="text-muted-foreground text-xs">—</span>;
}

function PackageSheet({
  sheet,
  closeHref,
  runningKernel,
}: {
  sheet: PackageVulnSheet;
  closeHref: string;
  runningKernel: string | null;
}) {
  const { pkg, vulns } = sheet;
  const withFinding = vulns.filter((v) => v.hasFinding).length;
  const otherKernel = isOtherKernel(pkg.kernelRelease, runningKernel);
  let kernelNote: string | null = null;
  if (pkg.kernelRelease) {
    kernelNote =
      runningKernel === null
        ? "The running kernel is unknown, so this kernel's vulnerabilities are raised as findings like any installed kernel's."
        : pkg.kernelRelease === runningKernel
          ? "This is the running kernel."
          : `Not the running kernel (${runningKernel}): these apply only if the host boots into ${pkg.kernelRelease}, so no findings are raised for them.`;
  }

  return (
    <UrlSheet
      key={pkg.softwareId}
      closeHref={closeHref}
      title={
        <>
          {pkg.name} <span className="font-mono text-sm font-normal">{pkg.version}</span>
        </>
      }
      description={
        <>
          {pkg.arch && `${pkg.arch} · `}
          {pkg.sourceName && pkg.sourceName !== pkg.name && `source ${pkg.sourceName} · `}
          {vulns.length === 0
            ? "no known vulnerabilities"
            : `${vulns.length} known ${vulns.length === 1 ? "vulnerability" : "vulnerabilities"}, ${withFinding} open on this host`}
          {!pkg.installed && " · no longer installed"}
        </>
      }
    >
      <div className="flex flex-col gap-3 text-sm">
        {kernelNote && (
          <Alert>
            <Info className="size-4" />
            <AlertDescription>{kernelNote}</AlertDescription>
          </Alert>
        )}
        {pkg.maxFixedVersion && (
          <p>
            Upgrade to <span className="font-mono text-xs">{pkg.maxFixedVersion}</span> or later to
            fix every vulnerability that has a standard-archive fix.
          </p>
        )}
        {pkg.matchSource === null && vulns.length === 0 && (
          <p className="text-muted-foreground">
            This package isn&apos;t matched against advisories (not a deb from a supported release,
            or a kernel metapackage/header package).
          </p>
        )}
        <ul className="flex flex-col divide-y rounded-lg border">
          {vulns.map((v) => (
            <li key={v.vulnKey} className="flex flex-col gap-1 px-3 py-2.5">
              <div className="flex flex-wrap items-center gap-1.5">
                <Link href={vulnHref(v.vulnKey)} className="font-medium hover:underline">
                  {v.vulnKey}
                </Link>
                {v.hasFinding ? (
                  <SeverityBadge severity={v.severity} />
                ) : (
                  <Badge
                    variant="outline"
                    className="text-muted-foreground font-normal"
                    title={
                      otherKernel
                        ? "Not the running kernel: informational, no finding raised"
                        : "No open finding on this host for this match"
                    }
                  >
                    {otherKernel ? "info · not the running kernel" : "no open finding"}
                  </Badge>
                )}
                {v.isKev && <KevBadge />}
              </div>
              {v.description && (
                <p className="text-muted-foreground line-clamp-3 text-xs">{v.description}</p>
              )}
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <ScoreLine
                  epss={v.epssScore}
                  cvss={v.cvssV3Score}
                  distroSeverity={v.distroSeverity}
                />
              </div>
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span className="text-muted-foreground">Fixed in</span>
                <FixCell fixedVersion={v.fixedVersion} fixChannel={v.fixChannel} />
              </div>
              <AdvisoryLinks ids={v.advisoryIds} />
            </li>
          ))}
        </ul>
      </div>
    </UrlSheet>
  );
}
