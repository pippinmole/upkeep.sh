import { Container } from "lucide-react";
import Link from "next/link";

import { EmptyState } from "@/components/empty-state";
import { ImageScoreCell } from "@/components/image/score-cell";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle as UiCardTitle,
} from "@/components/ui/card";
import { KevBadge } from "@/components/vuln/badges";
import { imageHref, platformLabel, shortImageId } from "@/lib/image-key";
import type { ImageOverviewStats, OverviewImage } from "@/lib/queries-overview-images";
import { cn } from "@/lib/utils";

import { plural, SeverityBars } from "./cards";

// The Overview page's "Container images" section: vulnerabilities in the
// packages inside images that containers on the user's hosts use. Never
// added to the host package numbers: these are fixed by rebuilding or
// re-pulling the image, not by upgrading the host.

const IMAGES = "/dashboard/images";
const VULNS = "/dashboard/vulnerabilities";
const MAX_HOSTS = 2;

function imageName(img: OverviewImage): string {
  return img.tags[0] ?? shortImageId(img.key.imageId);
}

function MostVulnerable({ images }: { images: OverviewImage[] }) {
  if (images.length === 0) {
    return (
      <p className="text-muted-foreground text-sm">
        No image a container uses has known vulnerabilities.
      </p>
    );
  }
  return (
    <div className="flex flex-col gap-1">
      <h3 className="text-muted-foreground text-xs font-medium tracking-wide uppercase">
        Most vulnerable in use
      </h3>
      <ul className="divide-y">
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
              className="grid gap-x-4 gap-y-1 py-2.5 sm:grid-cols-[minmax(0,2fr)_minmax(0,1.2fr)_minmax(0,2fr)] sm:items-center"
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
    </div>
  );
}

// Images the dashboard can't score yet, or whose OS release it doesn't
// assess, and why: one line, linking to the Images page where each image
// says what it needs.
function CoverageLine({ s }: { s: ImageOverviewStats }) {
  const parts = [
    s.needsAgent > 0 && `${plural(s.needsAgent, "image needs", "images need")} the agent`,
    s.noSbom > 0 && `${plural(s.noSbom, "image", "images")} without an SBOM`,
    s.failing > 0 && `${plural(s.failing, "package list fetch", "package list fetches")} failing`,
    s.pending > 0 && `${plural(s.pending, "image", "images")} waiting for a package list`,
    s.releaseNotAssessed > 0 &&
      `${plural(s.releaseNotAssessed, "image", "images")} on an out-of-support or unrecognised OS release`,
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

export function ContainerImagesSection({
  stats: s,
  className,
}: {
  stats: ImageOverviewStats;
  className?: string;
}) {
  const f = s.findings;
  return (
    <Card className={cn("gap-4", className)}>
      <CardHeader>
        <UiCardTitle>Container images</UiCardTitle>
        <CardDescription>
          Packages inside the images your containers use. Fixed by rebuilding or re-pulling the
          image, not by upgrading the host.
        </CardDescription>
        <CardAction>
          <Link
            href={IMAGES}
            className="text-muted-foreground hover:text-foreground text-sm hover:underline"
          >
            All images
          </Link>
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {!s.hasDocker ? (
          <EmptyState
            size="inline"
            icon={Container}
            title="No Docker data yet"
            description="Container images are scored once an agent can read the host's Docker socket. A host's Containers tab explains how."
            action={
              <Button asChild size="sm" variant="outline">
                <Link href="/dashboard/hosts">Choose a host</Link>
              </Button>
            }
          />
        ) : (
          <>
            <div className="grid gap-4 sm:grid-cols-[auto_minmax(0,1fr)] sm:items-start sm:gap-8">
              <div className="flex flex-col gap-1">
                <p className="text-3xl font-semibold tabular-nums">
                  {s.vulnerable}
                  <span className="text-muted-foreground text-base font-normal">
                    {" "}
                    of {plural(s.scored, "image", "images")} vulnerable
                  </span>
                </p>
                <p className="text-muted-foreground text-sm">
                  <Link href={`${VULNS}?kind=image`} className="hover:underline">
                    {plural(f.open, "open finding", "open findings")}
                  </Link>{" "}
                  on {plural(f.hosts, "host", "hosts")}
                </p>
                {f.kev > 0 && (
                  <p className="text-muted-foreground flex items-center gap-2 text-sm">
                    <Link href={`${VULNS}?kind=image&kev=1`}>
                      <KevBadge count={f.kev} />
                    </Link>{" "}
                    rebuild or re-pull first
                  </p>
                )}
              </div>
              {f.open === 0 ? (
                <p className="text-muted-foreground text-sm">No open image findings.</p>
              ) : (
                <SeverityBars
                  counts={f.bySeverity}
                  total={f.open}
                  href={(sev) => `${VULNS}?kind=image&severity=${sev}`}
                />
              )}
            </div>
            <MostVulnerable images={s.top} />
            <CoverageLine s={s} />
          </>
        )}
      </CardContent>
    </Card>
  );
}
