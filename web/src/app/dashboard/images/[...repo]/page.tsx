import { ArrowLeft, X } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import {
  ContainerStateBadge,
  HostLink,
  WARN_BADGE,
  shortId,
} from "@/components/docker-fleet/badges";
import { DockerCoverageNote } from "@/components/docker-fleet/coverage-note";
import { repoHref } from "@/components/docker-fleet/links";
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
import { imageHref } from "@/lib/image-key";
import {
  type RepoHostImage,
  UNTAGGED_REPO,
  getDockerCoverage,
  getRepoImages,
  tagDrifts,
} from "@/lib/queries-docker-fleet";
import { param, type SearchParams } from "@/lib/search-params";
import { formatDate, formatDateTime } from "@/lib/time";
import { cn } from "@/lib/utils";

type Params = Promise<{ repo: string[] }>;

const NO_TAG = "<none>";

// Catch-all segments arrive percent-decoded; the repository is compared by
// equality as a bound parameter, so only its length is capped.
async function repoName(params: Params): Promise<string> {
  return (await params).repo.join("/").slice(0, 300);
}

export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  const repo = await repoName(params);
  return { title: `${repo === UNTAGGED_REPO ? "Untagged" : repo} · Images` };
}

type TagSummary = {
  tag: string; // NO_TAG = digest only
  imageIds: string[];
  digests: string[];
  platforms: string[];
  hosts: number;
};

function summarizeTags(rows: RepoHostImage[]): TagSummary[] {
  const m = new Map<
    string,
    { ids: Set<string>; digests: Set<string>; platforms: Set<string>; hosts: Set<string> }
  >();
  for (const r of rows) {
    for (const tag of r.tags.length ? r.tags : [NO_TAG]) {
      const e = m.get(tag) ?? {
        ids: new Set(),
        digests: new Set(),
        platforms: new Set(),
        hosts: new Set(),
      };
      e.ids.add(r.imageId);
      for (const d of r.digests) e.digests.add(d);
      if (r.platform) e.platforms.add(r.platform);
      e.hosts.add(r.hostId);
      m.set(tag, e);
    }
  }
  return [...m.entries()]
    .map(([tag, e]) => ({
      tag,
      imageIds: [...e.ids].sort(),
      digests: [...e.digests].sort(),
      platforms: [...e.platforms].sort(),
      hosts: e.hosts.size,
    }))
    .sort((a, b) => (a.tag === NO_TAG ? 1 : b.tag === NO_TAG ? -1 : a.tag.localeCompare(b.tag)));
}

function matchesId(full: string, q: string): boolean {
  const bare = (s: string) => s.replace(/^sha256:/, "").toLowerCase();
  return bare(full).startsWith(bare(q));
}

export default async function FleetImagePage({
  params,
  searchParams,
}: {
  params: Params;
  searchParams: Promise<SearchParams>;
}) {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  const userId = session.user.id;
  const [repo, sp] = await Promise.all([repoName(params), searchParams]);
  const untagged = repo === UNTAGGED_REPO;
  const repoKey = untagged ? "" : repo;

  const filter = {
    tag: param(sp, "tag"),
    digest: param(sp, "digest"),
    image: param(sp, "image"),
  };
  const [rows, coverage] = await Promise.all([
    getRepoImages(userId, repo),
    getDockerCoverage(userId),
  ]);

  const tags = untagged ? [] : summarizeTags(rows);
  const filtered = rows.filter(
    (r) =>
      (!filter.tag ||
        (filter.tag === NO_TAG ? r.tags.length === 0 : r.tags.includes(filter.tag))) &&
      (!filter.digest || r.digests.some((d) => matchesId(d, filter.digest!))) &&
      (!filter.image || matchesId(r.imageId, filter.image)),
  );
  const filterLabel = filter.tag
    ? `tag ${filter.tag}`
    : filter.digest
      ? `digest ${shortId(filter.digest)}`
      : filter.image
        ? `image ID ${shortId(filter.image)}`
        : null;

  const hostCount = new Set(rows.map((r) => r.hostId)).size;
  const idCount = new Set(rows.map((r) => r.imageId)).size;
  const running = rows.reduce(
    (n, r) => n + r.containers.filter((c) => c.state === "running").length,
    0,
  );

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-6 p-4 sm:p-6">
      <div>
        <Link
          href="/dashboard/images"
          className="text-muted-foreground hover:text-foreground inline-flex items-center gap-1 text-sm"
        >
          <ArrowLeft className="size-3.5" />
          All images
        </Link>
        <h1 className={cn("mt-2 text-2xl font-bold break-all", !untagged && "font-mono")}>
          {untagged ? "Untagged images" : repo}
        </h1>
        <p className="text-muted-foreground text-sm">
          {hostCount === 0
            ? "Not currently present on any of your hosts."
            : `${idCount} image ID${idCount === 1 ? "" : "s"} on ${hostCount} host${hostCount === 1 ? "" : "s"}, ${running} running container${running === 1 ? "" : "s"}.`}
        </p>
      </div>

      {rows.length === 0 && <DockerCoverageNote coverage={coverage} />}

      {tags.length > 0 && (
        <section className="flex flex-col gap-2">
          <h2 className="font-semibold">Tags</h2>
          <p className="text-muted-foreground -mt-1 text-sm">
            A tag flagged as varying points to different image content on different hosts (more than
            one digest, or more image IDs than platforms): some hosts have an older or locally built
            image under the same name.
          </p>
          <div className="bg-card rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Tag</TableHead>
                  <TableHead>Image IDs</TableHead>
                  <TableHead>Digests</TableHead>
                  <TableHead>Platforms</TableHead>
                  <TableHead className="text-right">Hosts</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tags.map((t) => {
                  const drift =
                    t.tag !== NO_TAG &&
                    tagDrifts({
                      digests: t.digests.length,
                      imageIds: t.imageIds.length,
                      platforms: t.platforms.length,
                    });
                  return (
                    <TableRow key={t.tag}>
                      <TableCell className="align-top">
                        <div className="flex flex-wrap items-center gap-2">
                          <Link
                            href={repoHref(repoKey, { tag: t.tag })}
                            className={cn(
                              "font-mono text-sm hover:underline",
                              t.tag === NO_TAG && "text-muted-foreground italic",
                            )}
                          >
                            {t.tag}
                          </Link>
                          {drift && (
                            <Badge variant="outline" className={WARN_BADGE}>
                              varies across hosts
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="align-top font-mono text-xs">
                        <div className="flex flex-col gap-0.5">
                          {t.imageIds.map((id) => (
                            <Link
                              key={id}
                              href={repoHref(repoKey, { image: id })}
                              title={id}
                              className="hover:underline"
                            >
                              {shortId(id)}
                            </Link>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell className="align-top font-mono text-xs">
                        {t.digests.length === 0 ? (
                          <span className="text-muted-foreground font-sans">
                            none (built locally or loaded)
                          </span>
                        ) : (
                          <div className="flex flex-col gap-0.5">
                            {t.digests.map((d) => (
                              <Link
                                key={d}
                                href={repoHref(repoKey, { digest: d })}
                                title={d}
                                className="hover:underline"
                              >
                                {shortId(d)}
                              </Link>
                            ))}
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="text-muted-foreground align-top text-xs">
                        {t.platforms.join(", ") || "—"}
                      </TableCell>
                      <TableCell className="text-right align-top tabular-nums">{t.hosts}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </section>
      )}

      {rows.length > 0 && (
        <section className="flex flex-col gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="font-semibold">
              Hosts with {untagged ? "untagged images" : <span className="font-mono">{repo}</span>}
            </h2>
            {filterLabel && (
              <Link href={repoHref(repoKey)}>
                <Badge variant="secondary" className="gap-1 font-normal">
                  {filterLabel}
                  <X className="size-3" aria-label="Clear filter" />
                </Badge>
              </Link>
            )}
          </div>
          <div className="bg-card rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Host</TableHead>
                  {!untagged && <TableHead>Tags</TableHead>}
                  <TableHead>Image</TableHead>
                  <TableHead>Containers</TableHead>
                  <TableHead>First seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={untagged ? 4 : 5}
                      className="text-muted-foreground h-20 text-center"
                    >
                      No host has {filterLabel}.
                    </TableCell>
                  </TableRow>
                ) : (
                  filtered.map((r) => (
                    <TableRow key={`${r.hostId}:${r.imageId}`}>
                      <TableCell className="align-top">
                        <HostLink
                          hostId={r.hostId}
                          hostname={r.hostname}
                          label={r.label}
                          tab="images"
                        />
                      </TableCell>
                      {!untagged && (
                        <TableCell className="align-top">
                          <div className="flex flex-wrap gap-1">
                            {(r.tags.length ? r.tags : [NO_TAG]).map((t) => (
                              <Badge
                                key={t}
                                variant="outline"
                                className={cn(
                                  "font-mono text-xs font-normal",
                                  t === NO_TAG && "text-muted-foreground italic",
                                )}
                              >
                                {t}
                              </Badge>
                            ))}
                          </div>
                          {r.otherRefs.length > 0 && (
                            <div
                              className="text-muted-foreground mt-1 font-mono text-xs"
                              title="Other names for the same image on this host"
                            >
                              also {r.otherRefs.join(", ")}
                            </div>
                          )}
                        </TableCell>
                      )}
                      <TableCell className="align-top font-mono text-xs">
                        <div title={r.imageId}>{shortId(r.imageId)}</div>
                        {r.digests.map((d) => (
                          <div key={d} className="text-muted-foreground" title={d}>
                            @{shortId(d)}
                          </div>
                        ))}
                        <div className="text-muted-foreground font-sans">
                          {r.platform || (r.inspectError ? "details unavailable" : "—")}
                        </div>
                        {r.key && (
                          <Link
                            href={imageHref(r.key.imageId, { platform: r.key, host: r.hostId })}
                            className="font-sans hover:underline"
                          >
                            Packages and vulnerabilities
                          </Link>
                        )}
                      </TableCell>
                      <TableCell className="align-top">
                        {r.containers.length === 0 ? (
                          <span className="text-muted-foreground text-sm">None</span>
                        ) : (
                          <ul className="flex flex-col gap-1">
                            {r.containers.map((c) => (
                              <li key={c.id} className="flex flex-wrap items-center gap-2 text-sm">
                                <span className="font-mono text-xs">{c.name}</span>
                                <ContainerStateBadge state={c.state} />
                                {(c.composeProject || c.swarmServiceName) && (
                                  <span className="text-muted-foreground text-xs">
                                    {c.swarmServiceName
                                      ? `service ${c.swarmServiceName}`
                                      : `compose ${c.composeProject}`}
                                  </span>
                                )}
                              </li>
                            ))}
                          </ul>
                        )}
                      </TableCell>
                      <TableCell className="text-muted-foreground align-top whitespace-nowrap">
                        <span title={formatDateTime(r.firstSeenAt)}>
                          {formatDate(r.firstSeenAt)}
                        </span>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </section>
      )}
    </main>
  );
}
