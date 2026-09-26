import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { FilterBar } from "@/components/inventory/filter-bar";
import { Pager } from "@/components/inventory/pager";
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
import { auth } from "@/lib/auth";
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
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  const userId = session.user.id;
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
    getFleetVulns(userId, filters),
    getOverviewStats(userId),
  ]);
  const basePath = "/dashboard/vulnerabilities";
  const hasFilters = filters.q || filters.severity || filters.kev || filters.fix;

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-4 p-4 sm:p-6">
      <div>
        <h1 className="text-2xl font-bold">Vulnerabilities</h1>
        <p className="text-muted-foreground text-sm">
          Known vulnerabilities in packages installed on your hosts, most urgent first (known
          exploited, then exploit likelihood, then distro priority).
        </p>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <SegmentedLinks
          label="Vulnerability status"
          items={[
            {
              href: `${basePath}${withParams(sp, { status: null, page: null })}`,
              label: `Affecting hosts (${stats.distinctOpenVulns})`,
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
        hidden={{ status: status === "resolved" ? "resolved" : null }}
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
                  {hasFilters
                    ? "No vulnerabilities match these filters."
                    : status === "open"
                      ? stats.hosts === 0
                        ? "No hosts yet. Register an agent to start matching its packages."
                        : "No open vulnerabilities on any host."
                      : "No vulnerabilities have been resolved on every host yet."}
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
                      <p className="text-muted-foreground line-clamp-2 text-xs whitespace-normal">
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
                    <span className="line-clamp-2 max-w-56 text-sm whitespace-normal">
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
