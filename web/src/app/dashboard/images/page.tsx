import { Container, Plus } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { RegistryLogo } from "@/components/brand";
import { DockerCoverageNote } from "@/components/docker-fleet/coverage-note";
import { repoHref } from "@/components/docker-fleet/links";
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
import { ImageScoreCell } from "@/components/image/score-cell";
import { requireViewer } from "@/lib/viewer";
import { imageHref } from "@/lib/image-key";
import {
  getDockerCoverage,
  getFleetImages,
  getRepoScores,
  type RepoScore,
  tagDrifts,
} from "@/lib/queries-docker-fleet";
import { pageParam, param, type SearchParams } from "@/lib/search-params";
import { cn } from "@/lib/utils";

export const metadata: Metadata = {
  title: "Images",
};

const PAGE_SIZE = 50;
const BASE_PATH = "/dashboard/images";
const MAX_TAGS = 6;

// The repository's most urgent image, linked to its detail page; the
// repository page lists every image with its own score.
function RepoScoreCell({ sc }: { sc: RepoScore | undefined }) {
  if (!sc) {
    return (
      <span
        className="text-muted-foreground text-xs"
        title="No host has inspected these images yet"
      >
        Not inspected
      </span>
    );
  }
  return (
    <div className="flex flex-col items-start gap-0.5">
      <ImageScoreCell
        score={sc.score}
        inspected
        hasRepoDigest={sc.hasRepoDigest}
        href={imageHref(sc.key.imageId, { platform: sc.key })}
      />
      {sc.keys > 1 && (
        <span className="text-muted-foreground text-xs">worst of {sc.keys} images</span>
      )}
    </div>
  );
}

export default async function FleetImagesPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const { workspaceId } = await requireViewer();
  const sp = await searchParams;

  const filters = {
    q: param(sp, "q"),
    sort: param(sp, "sort") === "hosts" ? ("hosts" as const) : ("name" as const),
    page: pageParam(sp),
    pageSize: PAGE_SIZE,
  };
  const [{ rows, total }, coverage] = await Promise.all([
    getFleetImages(workspaceId, filters),
    getDockerCoverage(workspaceId),
  ]);
  const scores = await getRepoScores(
    workspaceId,
    rows.map((r) => r.repo),
  );

  const header = (
    <PageHeader
      title="Images"
      description={
        total > 0 && !filters.q
          ? `Docker images currently present on your hosts, in ${total.toLocaleString("en-US")} ${total === 1 ? "repository" : "repositories"}.`
          : "Docker images currently present on your hosts, by repository."
      }
    />
  );

  // No image reported at all (not a search miss): Docker collection is
  // opt-in on the agent, so say how to turn it on.
  if (total === 0 && !filters.q && filters.page === 1) {
    return (
      <main className="flex min-h-0 flex-1 flex-col gap-4 p-4 sm:p-6">
        {header}
        <DockerCoverageNote coverage={coverage} />
        {coverage.hosts === 0 ? (
          <EmptyState
            size="page"
            icon={Container}
            title="No hosts yet"
            description="Images are reported by the agent on each Docker host. Add a host to start."
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
            icon={Container}
            title="No Docker images reported"
            description={
              <>
                Docker collection is enabled per agent, on the Docker host itself: mount{" "}
                <code className="font-mono text-xs">/var/run/docker.sock</code> into the
                agent&apos;s container. Images appear after its next report.
              </>
            }
            action={
              <Button asChild variant="outline">
                <Link href="/dashboard/hosts">Go to hosts</Link>
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

      <DockerCoverageNote coverage={coverage} />

      <FilterBar
        action={BASE_PATH}
        q={filters.q}
        qPlaceholder="Search name, tag, digest or ID…"
        qLabel="Search images"
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
              <TableHead>Repository</TableHead>
              <TableHead>Tags</TableHead>
              <TableHead>Vulnerabilities</TableHead>
              <TableHead className="text-right">Image IDs</TableHead>
              <TableHead className="text-right">Hosts</TableHead>
              <TableHead className="text-right">Running containers</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-muted-foreground h-24 text-center">
                  {filters.q ? (
                    <NoMatches things="images" clearHref={clearFiltersHref(BASE_PATH)} />
                  ) : (
                    "Nothing on this page."
                  )}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((r) => {
                const shown = r.tags.slice(0, MAX_TAGS);
                return (
                  <TableRow key={r.repo || "(untagged)"}>
                    <TableCell className="max-w-sm align-top">
                      <span className="flex min-w-0 items-center gap-2">
                        <RegistryLogo repo={r.repo} className="text-muted-foreground shrink-0" />
                        <Link
                          href={repoHref(r.repo)}
                          className={cn(
                            "truncate font-medium hover:underline",
                            r.repo ? "font-mono text-sm" : "text-muted-foreground italic",
                          )}
                          title={r.repo || undefined}
                        >
                          {r.repo || "Untagged images"}
                        </Link>
                      </span>
                    </TableCell>
                    <TableCell className="align-top">
                      {r.repo === "" ? (
                        <span className="text-muted-foreground text-xs">
                          No tag or digest (dangling or build cache)
                        </span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {shown.map((t) => {
                            const drift = t.tag !== null && tagDrifts(t);
                            return (
                              <Link
                                key={t.tag ?? ""}
                                href={repoHref(r.repo, { tag: t.tag ?? "<none>" })}
                                title={
                                  drift
                                    ? `${t.imageIds} image IDs / ${t.digests} digests across ${t.hosts} hosts: this tag doesn't point to the same image everywhere`
                                    : `${t.hosts} host${t.hosts === 1 ? "" : "s"}`
                                }
                              >
                                <Badge
                                  variant={drift ? "warning" : "outline"}
                                  className={cn(
                                    "font-mono text-xs font-normal",
                                    t.tag === null && "text-muted-foreground italic",
                                  )}
                                >
                                  {t.tag ?? "<none>"}
                                  {drift && ` · ${Math.max(t.digests, t.imageIds)} variants`}
                                </Badge>
                              </Link>
                            );
                          })}
                          {r.tags.length > shown.length && (
                            <span className="text-muted-foreground self-center text-xs">
                              +{r.tags.length - shown.length} more
                            </span>
                          )}
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="align-top">
                      <RepoScoreCell sc={scores.get(r.repo)} />
                    </TableCell>
                    <TableCell className="text-right align-top tabular-nums">
                      {r.imageIds}
                    </TableCell>
                    <TableCell className="text-right align-top tabular-nums">{r.hosts}</TableCell>
                    <TableCell className="text-right align-top tabular-nums">
                      {r.runningContainers}
                    </TableCell>
                  </TableRow>
                );
              })
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
