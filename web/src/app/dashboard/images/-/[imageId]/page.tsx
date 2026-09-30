import { ScanSearch } from "lucide-react";
import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { PageHeader } from "@/components/layout/page-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { SegmentedLinks } from "@/components/vuln/links";
import { requireViewer } from "@/lib/viewer";
import {
  imageHref,
  imageIdParam,
  parsePlatform,
  shortImageId,
  type ImageKey,
  type ImageTab,
} from "@/lib/image-key";
import { getImageOverview, getImagePlatforms } from "@/lib/queries-image";
import { oneOf, param, type SearchParams } from "@/lib/search-params";

import { ImageHeader, imageTitle } from "./image-header";
import { ImageListStateNote, listView } from "./list-state";
import { PackagesTab, VulnsTab } from "./tabs";

// One container image: header (names, platform, list provenance, score,
// hosts and containers), then Packages (every package, vulnerable or not)
// and Vulnerabilities (matches grouped per source package) as server-driven
// tables. Route and key rules: lib/image-key.ts. Scoped to the signed-in
// user: 404 unless one of their hosts currently has the image.

type Params = Promise<{ imageId: string }>;

async function resolve(imageId: string, sp: SearchParams) {
  const { workspaceId } = await requireViewer();
  const plats = await getImagePlatforms(workspaceId, imageId, param(sp, "host"));
  if (!plats) notFound();
  const want = parsePlatform(param(sp, "platform"));
  const key: ImageKey | undefined = want
    ? plats.platforms.find(
        (p) => p.os === want.os && p.arch === want.arch && p.variant === want.variant,
      )
    : plats.platforms[0];
  if (want && !key) notFound();
  return { workspaceId, plats, key: key ?? null };
}

export async function generateMetadata({
  params,
  searchParams,
}: {
  params: Params;
  searchParams: Promise<SearchParams>;
}): Promise<Metadata> {
  const [{ imageId: raw }, sp] = await Promise.all([params, searchParams]);
  const imageId = imageIdParam(raw);
  const { workspaceId, key } = await resolve(imageId, sp);
  const o = key ? await getImageOverview(workspaceId, key) : null;
  return { title: `${o ? imageTitle(o) : shortImageId(imageId)} · Images` };
}

export default async function ImagePage({
  params,
  searchParams,
}: {
  params: Params;
  searchParams: Promise<SearchParams>;
}) {
  const [{ imageId: raw }, sp] = await Promise.all([params, searchParams]);
  const imageId = imageIdParam(raw);
  const { workspaceId, plats, key } = await resolve(imageId, sp);

  if (!key) {
    // Present on the user's hosts, but no host has inspected it yet, so the
    // platform (half of the key) isn't known.
    return (
      <main className="flex min-h-0 flex-1 flex-col gap-4 p-4 sm:p-6">
        <PageHeader
          breadcrumbs={[
            { label: "Images", href: "/dashboard/images" },
            { label: shortImageId(imageId) },
          ]}
          title={shortImageId(imageId)}
          mono
        />
        <Alert>
          <ScanSearch className="size-4" />
          <AlertTitle>Not inspected on any host yet</AlertTitle>
          <AlertDescription>
            The agent lists this image but hasn&apos;t inspected it successfully, so its platform
            isn&apos;t known and no package list can be looked up. It&apos;s retried on the
            agent&apos;s next push.
          </AlertDescription>
        </Alert>
      </main>
    );
  }

  const overview = await getImageOverview(workspaceId, key);
  if (!overview) notFound();
  const tab: ImageTab = oneOf(sp, "tab", ["packages", "vulnerabilities"] as const) ?? "packages";
  const view = listView(overview);
  const s = overview.score;
  const tabHref = (t: ImageTab) => imageHref(key.imageId, { platform: key, tab: t });

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-6 p-4 sm:p-6">
      <ImageHeader
        overview={overview}
        platforms={plats.platforms}
        uninspected={plats.uninspected}
      />
      <ImageListStateNote overview={overview} />
      {view === "tables" && (
        <section className="flex flex-col gap-3">
          <SegmentedLinks
            label="Image tabs"
            items={[
              {
                href: tabHref("packages"),
                label: `Packages${s && s.packages !== null ? ` (${s.packages})` : ""}`,
                active: tab === "packages",
              },
              {
                href: tabHref("vulnerabilities"),
                label: `Vulnerabilities${s?.scored && s.vulns !== null ? ` (${s.vulns})` : ""}`,
                active: tab === "vulnerabilities",
              },
            ]}
          />
          {tab === "packages" ? (
            <PackagesTab workspaceId={workspaceId} imageKey={key} sp={sp} />
          ) : (
            <VulnsTab
              workspaceId={workspaceId}
              imageKey={key}
              sp={sp}
              notAssessed={s?.notAssessed ?? 0}
            />
          )}
        </section>
      )}
    </main>
  );
}
