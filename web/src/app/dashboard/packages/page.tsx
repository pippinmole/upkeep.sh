import type { Metadata } from "next";
import { redirect } from "next/navigation";
import Link from "next/link";

import { FilterBar } from "@/components/inventory/filter-bar";
import { Pager } from "@/components/inventory/pager";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { auth } from "@/lib/auth";
import { getFleetEcosystems, getFleetPackages } from "@/lib/queries-inventory";
import { filterParam, pageParam, param, type SearchParams } from "@/lib/search-params";

export const metadata: Metadata = {
  title: "Packages",
};

const PAGE_SIZE = 50;

export default async function FleetPackagesPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  const userId = session.user.id;
  const sp = await searchParams;

  const filters = {
    q: param(sp, "q"),
    ecosystem: filterParam(sp, "ecosystem"),
    sort: param(sp, "sort") === "hosts" ? ("hosts" as const) : ("name" as const),
    page: pageParam(sp),
    pageSize: PAGE_SIZE,
  };
  const [{ rows, total }, ecosystems] = await Promise.all([
    getFleetPackages(userId, filters),
    getFleetEcosystems(userId),
  ]);

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-4 p-4 sm:p-6">
      <div>
        <h1 className="text-2xl font-bold">Packages</h1>
        <p className="text-muted-foreground text-sm">
          Software currently installed across your hosts.
        </p>
      </div>

      <FilterBar
        action="/dashboard/packages"
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
                  {filters.q || filters.ecosystem
                    ? "No installed packages match these filters."
                    : "No package inventory has been reported by your hosts yet."}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((r) => (
                <TableRow key={`${r.ecosystem}:${r.name}`}>
                  <TableCell>
                    <Link
                      href={`/dashboard/packages/${encodeURIComponent(r.name)}`}
                      className="font-medium hover:underline"
                    >
                      {r.name}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="font-normal">
                      {r.ecosystem}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {r.sampleVersions.join(", ")}
                    {r.versions > r.sampleVersions.length && (
                      <span className="text-muted-foreground">
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
        basePath="/dashboard/packages"
        searchParams={sp}
        page={filters.page}
        pageSize={PAGE_SIZE}
        total={total}
      />
    </main>
  );
}
