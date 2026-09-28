import type { Metadata } from "next";

import { hostTitle, requireHost } from "@/lib/host-page";
import { getHostImages } from "@/lib/queries-docker";

import { DockerCollectionState } from "../docker-collection-state";
import { FactFreshnessNote } from "../fact-freshness";
import { ImagesTable } from "./images-table";

type Params = Promise<{ hostId: string }>;

export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  const { host } = await requireHost((await params).hostId);
  return { title: `Images · ${hostTitle(host)}` };
}

// Current Docker images on the host (open host_images ranges) with how many
// of the host's containers run each one.
export default async function HostImagesPage({ params }: { params: Params }) {
  const { userId, host } = await requireHost((await params).hostId);
  const { rows, freshness } = await getHostImages(userId, host.id);
  const used = rows.filter((r) => r.containers > 0).length;

  return (
    <div className="flex flex-col gap-3">
      <div>
        <h2 className="font-semibold">
          Images{" "}
          {rows.length > 0 && (
            <span className="text-muted-foreground text-sm font-normal">
              {rows.length} images, {used} used by containers
            </span>
          )}
        </h2>
        {freshness && <FactFreshnessNote label="images" freshness={freshness} />}
      </div>
      <DockerCollectionState
        userId={userId}
        hostId={host.id}
        what="images"
        collectorStatus={host.latestSnapshot?.collectorStatus}
        freshness={freshness}
        hasRows={rows.length > 0}
      />
      {rows.length > 0 && <ImagesTable rows={rows} />}
    </div>
  );
}
