import { Cog } from "lucide-react";
import type { Metadata } from "next";

import { hostTitle, requireHost } from "@/lib/host-page";
import { getHostServices } from "@/lib/queries-host-facts";

import { FactEmptyState, FactFreshnessNote } from "../fact-freshness";
import { ServicesTable } from "./services-table";

type Params = Promise<{ hostId: string }>;

export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  const { host } = await requireHost((await params).hostId);
  return { title: `Services · ${hostTitle(host)}` };
}

// Current systemd services (open host_services ranges). Read from unit
// files and /proc cgroups by the agent, so state is running/stopped only
// (no "failed"; DOMAIN_MODEL.md §4.8).
export default async function HostServicesPage({ params }: { params: Params }) {
  const { workspaceId, host } = await requireHost((await params).hostId);
  const { rows, freshness } = await getHostServices(workspaceId, host.id);
  const running = rows.filter((r) => r.state === "running").length;

  return (
    <div className="flex flex-col gap-3">
      <div>
        <h2 className="font-semibold">
          Services{" "}
          {rows.length > 0 && (
            <span className="text-muted-foreground text-sm font-normal">
              {running} running of {rows.length}
            </span>
          )}
        </h2>
        <FactFreshnessNote label="services" freshness={freshness} />
      </div>
      {rows.length > 0 ? (
        <ServicesTable rows={rows} />
      ) : (
        freshness && (
          <FactEmptyState
            icon={Cog}
            title="No services"
            description="The agent found no systemd services on this host."
            collectors={["systemd_services"]}
            collectorStatus={host.latestSnapshot?.collectorStatus}
          />
        )
      )}
    </div>
  );
}
