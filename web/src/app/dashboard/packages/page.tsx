import { Package, Plus } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { EcosystemIcon } from "@/components/brand";
import { EmptyState } from "@/components/empty-state";
import { FilterBar } from "@/components/inventory/filter-bar";
import { clearFiltersHref, NoMatches } from "@/components/inventory/no-matches";
import { Pager } from "@/components/inventory/pager";
import { PageHeader } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { requireViewer } from "@/lib/viewer";
import { getFleetEcosystems, getFleetPackages } from "@/lib/queries-inventory";
import { filterParam, pageParam, param, type SearchParams } from "@/lib/search-params";

export const metadata: Metadata = {
  title: "Packages",
};

const PAGE_SIZE = 50;
const BASE_PATH = "/dashboard/packages";

export default async function FleetPackagesPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const { workspaceId } = await requireViewer();
  const sp = await searchParams;

  const filters = {
    q: param(sp, "q"),
    ecosystem: filterParam(sp, "ecosystem"),
    sort: param(sp, "sort") === "hosts" ? ("hosts" as const) : ("name" as const),
    page: pageParam(sp),
    pageSize: PAGE_SIZE,
  };
  const [{ rows, total }, ecosystems] = await Promise.all([
    getFleetPackages(workspaceId, filters),
    getFleetEcosystems(workspaceId),
  ]);
  const header = (
    <PageHeader
      title="Packages"
      description={
        total > 0 && !filters.q && !filters.ecosystem
          ? `${total.toLocaleString("en-US")} packages currently installed across your hosts.`
          : "Software currently installed across your hosts."
      }
    />
  );

  // No host has reported an inventory yet (an ecosystem exists once one has).
  if (ecosystems.length === 0) {
    return (
      <main className="flex min-h-0 flex-1 flex-col gap-6 p-4 sm:p-6">
        {header}
        <EmptyState
          size="page"
          icon={Package}
          title="No package inventory yet"
          description="Each host's agent reports its installed packages with every snapshot. Add a host to see them here."
          action={
            <Button asChild>
              <Link href="/dashboard/hosts">
                <Plus aria-hidden />
                Add a host
              </Link>
            </Button>
          }
        />
      </main>
    );
  }

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-4 p-4 sm:p-6">
      {header}

      <FilterBar
        action={BASE_PATH}
        q={filters.q}
        qPlaceholder="Search package or source…"
        ecosystem={{ value: filters.ecosystem, options: ecosystems }}
        sort={{
          value: filters.sort,
          options: [
            { value: "name", label: "Sort by name" },
            { value: "hosts", label: "Most hosts first" },
          ],
        }}
      />

      <div className="bg-card rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Package</TableHead>
              <TableHead>Ecosystem</TableHead>
              <TableHead>Versions in fleet</TableHead>
              <TableHead className="text-right">Hosts</TableHead>
              {/* P1b: "Vulnerable hosts" */}
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4} className="text-muted-foreground h-24 text-center">
                  {filters.q || filters.ecosystem ? (
                    <NoMatches things="packages" clearHref={clearFiltersHref(BASE_PATH)} />
                  ) : (
                    "Nothing on this page."
                  )}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((r) => (
                <TableRow key={`${r.ecosystem}:${r.name}`}>
                  <TableCell>
                    <Link
                      href={`${BASE_PATH}/${encodeURIComponent(r.name)}`}
                      className="font-medium hover:underline"
                    >
                      {r.name}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="font-normal">
                      <EcosystemIcon ecosystem={r.ecosystem} />
                      {r.ecosystem}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {r.sampleVersions.join(", ")}
                    {r.versions > r.sampleVersions.length && (
                      <span className="text-muted-foreground font-sans">
                        {" "}
                        +{r.versions - r.sampleVersions.length} more
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{r.hosts}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
      <Pager
        basePath={BASE_PATH}
        searchParams={sp}
        page={filters.page}
        pageSize={PAGE_SIZE}
        total={total}
      />
    </main>
  );
}
