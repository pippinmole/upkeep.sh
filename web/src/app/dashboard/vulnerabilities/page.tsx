import { Plus, ShieldCheck } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { EmptyState } from "@/components/empty-state";
import { FilterBar } from "@/components/inventory/filter-bar";
import { clearFiltersHref, NoMatches } from "@/components/inventory/no-matches";
import { Pager } from "@/components/inventory/pager";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  KevBadge,
  NoFixBadge,
  ProFixBadge,
  ScoreLine,
  SeverityBadge,
} from "@/components/vuln/badges";
import { SegmentedLinks, vulnHref } from "@/components/vuln/links";
import { requireViewer } from "@/lib/viewer";
import { type FixFilter, getFleetVulns, getOverviewStats } from "@/lib/queries-vulns";
import { oneOf, pageParam, param, type SearchParams, withParams } from "@/lib/search-params";
import { SEVERITIES, SEVERITY_LABEL } from "@/lib/severity";
import { formatDate, formatDateTime } from "@/lib/time";

export const metadata: Metadata = {
  title: "Vulnerabilities",
};

const PAGE_SIZE = 50;

export default async function FleetVulnerabilitiesPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const { workspaceId } = await requireViewer();
  const sp = await searchParams;

  const status = oneOf(sp, "status", ["open", "resolved"] as const) ?? "open";
  const filters = {
    status,
    q: param(sp, "q"),
    severity: oneOf(sp, "severity", SEVERITIES),
    kev: param(sp, "kev") === "1",
    fix: oneOf<FixFilter>(sp, "fix", ["available", "pro", "none"]),
    sort: oneOf(sp, "sort", ["severity", "hosts", "recent"] as const) ?? "severity",
    page: pageParam(sp),
    pageSize: PAGE_SIZE,
  };
  const [{ rows, total }, stats] = await Promise.all([
    getFleetVulns(workspaceId, filters),
    getOverviewStats(workspaceId),
  ]);
  const basePath = "/dashboard/vulnerabilities";
  const hasFilters = filters.q || filters.severity || filters.kev || filters.fix;
  const hidden = { status: status === "resolved" ? "resolved" : null };
  const header = (
    <PageHeader
      title="Vulnerabilities"
      description="Known vulnerabilities in packages installed on your hosts, ranked by real-world exploitability."
    />
  );

  // Nothing open anywhere (not a filter miss): say why and what's next.
  if (status === "open" && !hasFilters && stats.distinctOpenVulns === 0) {
    return (
      <main className="flex min-h-0 flex-1 flex-col gap-6 p-4 sm:p-6">
        {header}
        {stats.hosts === 0 ? (
          <EmptyState
            size="page"
            icon={ShieldCheck}
            title="No hosts yet"
            description="Vulnerabilities are matched against the packages your hosts report. Add a host to start."
            action={
              <Button asChild>
                <Link href="/dashboard/hosts">
                  <Plus aria-hidden />
                  Add a host
                </Link>
              </Button>
            }
          />
        ) : (
          <EmptyState
            size="page"
            icon={ShieldCheck}
            title="No open vulnerabilities"
            description={`No package on your ${stats.hosts === 1 ? "host" : `${stats.hosts} hosts`} matches a known vulnerability. New advisories are matched as they're published.`}
            action={
              <Button asChild variant="outline">
                <Link href={`${basePath}?status=resolved`}>Resolved vulnerabilities</Link>
              </Button>
            }
          />
        )}
      </main>
    );
  }

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-4 p-4 sm:p-6">
      {header}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <SegmentedLinks
          label="Vulnerability status"
          items={[
            {
              href: `${basePath}${withParams(sp, { status: null, page: null })}`,
              label: (
                <>
                  Affecting hosts
                  <span className="text-muted-foreground ml-1.5 tabular-nums">
                    {stats.distinctOpenVulns.toLocaleString("en-US")}
                  </span>
                </>
              ),
              active: status === "open",
            },
            {
              href: `${basePath}${withParams(sp, { status: "resolved", page: null })}`,
              label: "Resolved everywhere",
              active: status === "resolved",
            },
          ]}
        />
        {status === "open" && stats.vulns.kev > 0 && (
          <Link
            href={`${basePath}${withParams(sp, { kev: filters.kev ? null : "1", page: null })}`}
            className="text-sm"
            title="Show only known-exploited"
          >
            <KevBadge
              count={stats.vulns.kev}
              className={filters.kev ? "ring-ring ring-2 ring-offset-1" : undefined}
            />
            <span className="text-muted-foreground ml-1.5">
              known-exploited findings on {stats.hostsWithKev}{" "}
              {stats.hostsWithKev === 1 ? "host" : "hosts"}
            </span>
          </Link>
        )}
      </div>

      <FilterBar
        action={basePath}
        q={filters.q}
        qPlaceholder="CVE id or source package…"
        qLabel="Search vulnerabilities"
        hidden={hidden}
        selects={[
          {
            name: "severity",
            label: "Severity",
            value: filters.severity,
            allLabel: "All severities",
            options: SEVERITIES.map((s) => ({ value: s, label: SEVERITY_LABEL[s] })),
          },
          {
            name: "kev",
            label: "Known exploited",
            value: filters.kev ? "1" : null,
            allLabel: "KEV: any",
            options: [{ value: "1", label: "KEV only" }],
            className: "w-32",
          },
          {
            name: "fix",
            label: "Fix availability",
            value: filters.fix,
            allLabel: "Any fix status",
            options: [
              { value: "available", label: "Fix available" },
              { value: "pro", label: "Fix requires Pro" },
              { value: "none", label: "No fix yet" },
            ],
          },
        ]}
        sort={{
          value: filters.sort,
          options: [
            { value: "severity", label: "Most urgent" },
            { value: "hosts", label: "Most hosts" },
            { value: "recent", label: "Newest" },
          ],
        }}
      />

      <div className="bg-card rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Vulnerability</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead className="text-right">
                {status === "open" ? "Affected hosts" : "Previously affected"}
              </TableHead>
              <TableHead>Packages</TableHead>
              <TableHead>Fix</TableHead>
              <TableHead>First seen</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-muted-foreground h-24 text-center">
                  {hasFilters ? (
                    <NoMatches
                      things="vulnerabilities"
                      clearHref={clearFiltersHref(basePath, hidden)}
                    />
                  ) : status === "open" ? (
                    "Nothing on this page."
                  ) : (
                    "No vulnerabilities have been resolved on every host yet."
                  )}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((r) => (
                <TableRow key={r.vulnKey}>
                  <TableCell className="max-w-md align-top">
                    <Link href={vulnHref(r.vulnKey)} className="font-medium hover:underline">
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
                  </TableCell>
                  <TableCell className="align-top">
                    <div className="flex flex-col items-start gap-1">
                      <div className="flex flex-wrap gap-1">
                        <SeverityBadge severity={r.severity} />
                        {r.isKev && <KevBadge />}
                      </div>
                      <ScoreLine epss={r.epssScore} cvss={r.cvssV3Score} distroSeverity={null} />
                    </div>
                  </TableCell>
                  <TableCell className="text-right align-top tabular-nums">
                    {status === "open" ? r.affectedHosts : r.previousHosts}
                    {status === "open" && r.previousHosts > 0 && (
                      <span
                        className="text-muted-foreground block text-xs"
                        title="Hosts where a finding for this vulnerability was resolved"
                      >
                        +{r.previousHosts} resolved
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="align-top">
                    <span
                      className="line-clamp-2 max-w-56 text-sm whitespace-normal"
                      title={r.packages.join(", ") || undefined}
                    >
                      {r.packages.join(", ") || "—"}
                    </span>
                  </TableCell>
                  <TableCell className="align-top">
                    <div className="flex flex-col items-start gap-1">
                      {r.anyFix && <span className="text-sm">Available</span>}
                      {r.proOnly && <ProFixBadge />}
                      {r.noFix && <NoFixBadge />}
                    </div>
                  </TableCell>
                  <TableCell className="text-muted-foreground align-top whitespace-nowrap">
                    <span title={formatDateTime(r.firstSeenAt)}>{formatDate(r.firstSeenAt)}</span>
                  </TableCell>
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
    </main>
  );
}
