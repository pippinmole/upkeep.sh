import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { WARN_BADGE } from "@/components/docker-fleet/badges";
import { DockerCoverageNote } from "@/components/docker-fleet/coverage-note";
import { repoHref } from "@/components/docker-fleet/links";
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
import { ImageScoreCell } from "@/components/image/score-cell";
import { auth } from "@/lib/auth";
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
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  const userId = session.user.id;
  const sp = await searchParams;

  const filters = {
    q: param(sp, "q"),
    sort: param(sp, "sort") === "hosts" ? ("hosts" as const) : ("name" as const),
    page: pageParam(sp),
    pageSize: PAGE_SIZE,
  };
  const [{ rows, total }, coverage] = await Promise.all([
    getFleetImages(userId, filters),
    getDockerCoverage(userId),
  ]);
  const scores = await getRepoScores(
    userId,
    rows.map((r) => r.repo),
  );

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-4 p-4 sm:p-6">
      <div>
        <h1 className="text-2xl font-bold">Images</h1>
        <p className="text-muted-foreground text-sm">
          Docker images currently present on your hosts, by repository.
        </p>
      </div>

      <DockerCoverageNote coverage={coverage} />

      <FilterBar
        action="/dashboard/images"
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
                  {filters.q
                    ? "No images match this search."
                    : "No Docker images have been reported by your hosts yet."}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((r) => {
                const shown = r.tags.slice(0, MAX_TAGS);
                return (
                  <TableRow key={r.repo || "(untagged)"}>
                    <TableCell className="align-top">
                      <Link
                        href={repoHref(r.repo)}
                        className={cn(
                          "font-medium hover:underline",
                          r.repo ? "font-mono text-sm" : "text-muted-foreground italic",
                        )}
                      >
                        {r.repo || "Untagged images"}
                      </Link>
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
                                  variant="outline"
                                  className={cn(
                                    "font-mono text-xs font-normal",
                                    drift && WARN_BADGE,
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
        basePath="/dashboard/images"
        searchParams={sp}
        page={filters.page}
        pageSize={PAGE_SIZE}
        total={total}
      />
    </main>
  );
}
