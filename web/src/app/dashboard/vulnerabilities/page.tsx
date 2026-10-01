import { Plus, ShieldCheck } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { tableFacet, tableSort, tableStateFromParams } from "@/components/data-table/url-params";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { SegmentedLinks } from "@/components/vuln/links";
import { getFleetVulnCounts, getFleetVulnList } from "@/lib/queries-vuln-list";
import { oneOf, type SearchParams, withParams } from "@/lib/search-params";
import { SEVERITIES } from "@/lib/severity";
import { requireViewer } from "@/lib/viewer";
import { FLEET_VULN_SORTS, fleetVulnsTable, VULN_FIXES, VULN_KINDS } from "@/lib/vuln-tables";

import { FleetVulnsTable } from "./fleet-table";
import { KindSummary } from "./kind-summary";

export const metadata: Metadata = {
  title: "Vulnerabilities",
};

// Fleet Vulnerabilities (DOMAIN_MODEL.md §3.6): host package and container
// image findings in one server-driven table with a Kind facet; the counts
// above it are per kind, never summed.
export default async function FleetVulnerabilitiesPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const { workspaceId } = await requireViewer();
  const sp = await searchParams;

  const status = oneOf(sp, "status", ["open", "resolved"] as const) ?? "open";
  const state = tableStateFromParams(sp, fleetVulnsTable(status));
  const filters = {
    status,
    q: state.globalFilter || null,
    kinds: tableFacet(state, "kind", VULN_KINDS),
    severities: tableFacet(state, "severity", SEVERITIES),
    kev: tableFacet(state, "kev", ["1"]) !== null,
    fix: status === "open" ? tableFacet(state, "fix", VULN_FIXES) : null,
    sort: tableSort(state, FLEET_VULN_SORTS, status === "resolved" ? "seen" : "severity"),
    page: state.pagination.pageIndex + 1,
    pageSize: state.pagination.pageSize,
  };
  const [{ rows, total }, counts] = await Promise.all([
    getFleetVulnList(workspaceId, filters),
    getFleetVulnCounts(workspaceId),
  ]);
  const basePath = "/dashboard/vulnerabilities";
  // Switching status drops the sort (each status has its own default) and
  // the Fix facet, which Resolved doesn't have.
  const statusHref = (s: "open" | "resolved") =>
    `${basePath}${withParams(sp, { status: s === "open" ? null : s, page: null, sort: null, fix: null })}`;
  const filtered = filters.q || filters.kinds || filters.severities || filters.kev || filters.fix;
  const header = (
    <PageHeader
      title="Vulnerabilities"
      description="Known vulnerabilities in the packages installed on your hosts and in the container images they run, ranked by real-world exploitability."
    />
  );

  // Nothing open anywhere (not a filter miss): say why and what's next.
  const nothingOpen = counts.package.vulns === 0 && counts.image.vulns === 0;
  if (status === "open" && !filtered && nothingOpen) {
    return (
      <main className="flex min-h-0 flex-1 flex-col gap-6 p-4 sm:p-6">
        {header}
        {counts.hosts === 0 ? (
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
            description={`No package on your ${counts.hosts === 1 ? "host" : `${counts.hosts} hosts`}, or in the images their containers run, matches a known vulnerability. New advisories are matched as they're published.`}
            action={
              <Button asChild variant="outline">
                <Link href={`${basePath}?status=resolved`}>View resolved</Link>
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
              href: statusHref("open"),
              label: "Open",
              active: status === "open",
            },
            {
              href: statusHref("resolved"),
              label: "Resolved",
              active: status === "resolved",
            },
          ]}
        />
      </div>
      {status === "open" ? (
        <KindSummary counts={counts} basePath={basePath} />
      ) : (
        <p className="text-muted-foreground text-sm">
          No longer found on any host or in any image. A vulnerability moves back to Open if it
          reappears.
        </p>
      )}

      <FleetVulnsTable
        // Remount on status change: the columns differ.
        key={status}
        rows={rows}
        total={total}
        state={state}
        status={status}
        emptyMessage={
          status === "open"
            ? "Nothing on this page."
            : "Nothing resolved yet. A vulnerability appears here once no host or image is affected by it."
        }
      />
    </main>
  );
}
