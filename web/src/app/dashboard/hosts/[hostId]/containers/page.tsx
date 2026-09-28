import type { Metadata } from "next";

import { hostTitle, requireHost } from "@/lib/host-page";
import { getHostContainers, getHostDockerEngine } from "@/lib/queries-docker";

import { DockerCollectionState } from "../docker-collection-state";
import { FactFreshnessNote } from "../fact-freshness";
import { ContainersTable } from "./containers-table";
import { DockerEngineStrip } from "./docker-engine-strip";

type Params = Promise<{ hostId: string }>;

export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  const { host } = await requireHost((await params).hostId);
  return { title: `Containers · ${hostTitle(host)}` };
}

// Current Docker containers (open host_containers ranges), running or not,
// with the engine / Swarm facts above. Why the list is empty or stale comes
// from the newest snapshot's collector status (DockerCollectionState).
export default async function HostContainersPage({ params }: { params: Params }) {
  const { userId, host } = await requireHost((await params).hostId);
  const [{ rows, freshness }, engine] = await Promise.all([
    getHostContainers(userId, host.id),
    getHostDockerEngine(userId, host.id),
  ]);
  const running = rows.filter((r) => r.state === "running").length;

  return (
    <div className="flex flex-col gap-3">
      <div>
        <h2 className="font-semibold">
          Containers{" "}
          {rows.length > 0 && (
            <span className="text-muted-foreground text-sm font-normal">
              {running} running of {rows.length}
            </span>
          )}
        </h2>
        {freshness && <FactFreshnessNote label="containers" freshness={freshness} />}
      </div>
      <DockerCollectionState
        userId={userId}
        hostId={host.id}
        what="containers"
        collectorStatus={host.latestSnapshot?.collectorStatus}
        freshness={freshness}
        hasRows={rows.length > 0}
      />
      {engine && <DockerEngineStrip engine={engine} />}
      {rows.length > 0 && <ContainersTable rows={rows} />}
    </div>
  );
}
