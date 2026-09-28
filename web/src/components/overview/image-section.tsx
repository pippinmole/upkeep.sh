import Link from "next/link";

import { ImageScoreCell } from "@/components/image/score-cell";
import { KevBadge } from "@/components/vuln/badges";
import { imageHref, platformLabel, shortImageId } from "@/lib/image-key";
import type { ImageOverviewStats, OverviewImage } from "@/lib/queries-overview-images";

import { CardTitle, plural, SeverityBars, StatCard } from "./cards";

// The Overview page's "Container images" section: vulnerabilities in the
// packages inside images that containers on the user's hosts use. Never
// added to the host package numbers: these are fixed by rebuilding or
// re-pulling the image, not by upgrading the host.

const IMAGES = "/dashboard/images";
const MAX_HOSTS = 2;

function imageName(img: OverviewImage): string {
  return img.tags[0] ?? shortImageId(img.key.imageId);
}

function MostVulnerable({ images }: { images: OverviewImage[] }) {
  return (
    <section className="bg-card rounded-lg border">
      <div className="flex items-baseline justify-between gap-2 px-4 pt-4 pb-2">
        <CardTitle scope="Container images">Most vulnerable images in use</CardTitle>
        <Link
          href={IMAGES}
          className="text-muted-foreground hover:text-foreground text-sm hover:underline"
        >
          All images
        </Link>
      </div>
      {images.length === 0 ? (
        <p className="text-muted-foreground px-4 pb-4 text-sm">
          No image a container uses has known vulnerabilities.
        </p>
      ) : (
        <ul className="divide-y border-t">
          {images.map((img) => {
            const href = imageHref(img.key.imageId, {
              platform: img.key,
              tab: "vulnerabilities",
            });
            const shownHosts = img.hosts.slice(0, MAX_HOSTS);
            const more = img.hosts.length - shownHosts.length;
            return (
              <li
                key={`${img.key.imageId}|${platformLabel(img.key)}`}
                className="grid gap-x-4 gap-y-1 px-4 py-2.5 sm:grid-cols-[minmax(0,2fr)_minmax(0,1.2fr)_minmax(0,2fr)] sm:items-center"
              >
                <div className="min-w-0">
                  <Link
                    href={href}
                    className="block truncate font-medium hover:underline"
                    title={img.tags.join(", ") || img.key.imageId}
                  >
                    {imageName(img)}
                  </Link>
                  <span className="text-muted-foreground text-xs">
                    {platformLabel(img.key)}
                    {img.tags.length > 1 && ` · +${plural(img.tags.length - 1, "tag", "tags")}`}
                  </span>
                </div>
                <ImageScoreCell
                  score={img.score}
                  inspected
                  hasRepoDigest={img.hasRepoDigest}
                  href={href}
                />
                <ul className="text-muted-foreground min-w-0 text-sm">
                  {shownHosts.map((h) => (
                    <li key={h.hostId} className="truncate">
                      <Link
                        href={`/dashboard/hosts/${h.hostId}`}
                        className="text-foreground hover:underline"
                      >
                        {h.label || h.hostname}
                      </Link>
                      {": "}
                      <span title={h.containers.join(", ")}>{h.containers.join(", ")}</span>
                    </li>
                  ))}
                  {more > 0 && <li>and {plural(more, "more host", "more hosts")}</li>}
                </ul>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

// Images the dashboard can't score yet, and why: one line, linking to the
// Images page where each image says what it needs.
function CoverageLine({ s }: { s: ImageOverviewStats }) {
  const parts = [
    s.needsAgent > 0 && `${plural(s.needsAgent, "image needs", "images need")} the agent`,
    s.noSbom > 0 && `${plural(s.noSbom, "image", "images")} without an SBOM`,
    s.failing > 0 && `${plural(s.failing, "package list fetch", "package list fetches")} failing`,
    s.pending > 0 && `${plural(s.pending, "image", "images")} waiting for a package list`,
  ].filter((p): p is string => typeof p === "string");
  if (parts.length === 0) return null;
  return (
    <p className="text-muted-foreground text-sm">
      Not scored: {parts.join(", ")}.{" "}
      <Link href={IMAGES} className="text-foreground hover:underline">
        See Images
      </Link>
    </p>
  );
}

export function ContainerImagesSection({ stats: s }: { stats: ImageOverviewStats }) {
  if (!s.hasDocker) {
    return (
      <p className="text-muted-foreground text-sm">
        No Docker data yet: container images are scored once an agent can read the host&apos;s
        Docker socket.{" "}
        <Link href={IMAGES} className="text-foreground hover:underline">
          Images
        </Link>
      </p>
    );
  }
  const f = s.findings;
  return (
    <section className="flex flex-col gap-4">
      <div>
        <h2 className="text-lg font-semibold">Container images</h2>
        <p className="text-muted-foreground text-sm">
          Packages inside the images your containers use. Fixed by rebuilding or re-pulling the
          image, not by upgrading the host.
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <StatCard
          title="Images with vulnerabilities"
          value={
            <>
              {s.vulnerable}
              <span className="text-muted-foreground text-base font-normal">
                {" "}
                of {plural(s.scored, "image", "images")} scored
              </span>
            </>
          }
          href={IMAGES}
        >
          <p>
            {plural(f.open, "open finding", "open findings")} in{" "}
            {plural(f.images, "image", "images")} used by containers on{" "}
            {plural(f.hosts, "host", "hosts")}
          </p>
          <p className="mt-1 flex items-center gap-2">
            {f.kev > 0 ? (
              <>
                <KevBadge count={f.kev} />
                known exploited: rebuild or re-pull these first
              </>
            ) : (
              "No known-exploited vulnerabilities in images"
            )}
          </p>
        </StatCard>

        <section className="bg-card rounded-lg border p-4">
          <CardTitle scope="Container images">Open findings by severity</CardTitle>
          {f.open === 0 ? (
            <p className="text-muted-foreground mt-2 text-sm">No open image findings.</p>
          ) : (
            <SeverityBars counts={f.bySeverity} total={f.open} />
          )}
        </section>
      </div>

      <MostVulnerable images={s.top} />
      <CoverageLine s={s} />
    </section>
  );
}
