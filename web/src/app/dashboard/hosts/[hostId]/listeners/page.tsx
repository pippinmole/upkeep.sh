import type { Metadata } from "next";

import { hostTitle, requireHost } from "@/lib/host-page";
import { getHostListeners } from "@/lib/queries-host-facts";

import { FactFreshnessNote } from "../fact-freshness";
import { ListenersTable } from "./listeners-table";

type Params = Promise<{ hostId: string }>;

export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  const { host } = await requireHost((await params).hostId);
  return { title: `Listeners · ${hostTitle(host)}` };
}

// Current listening sockets (open host_listeners ranges): TCP in LISTEN
// state and bound, unconnected UDP sockets, with the owning process where
// the agent could read it. Whether a port is actually reachable from the
// internet depends on firewalls and is not known here.
export default async function HostListenersPage({ params }: { params: Params }) {
  const { userId, host } = await requireHost((await params).hostId);
  const { rows, freshness } = await getHostListeners(userId, host.id);
  const exposed = rows.filter((r) => r.wildcard).length;
  const latest =
    freshness.tcp && freshness.udp
      ? freshness.tcp.confirmedAt > freshness.udp.confirmedAt
        ? freshness.tcp
        : freshness.udp
      : (freshness.tcp ?? freshness.udp);

  return (
    <div className="flex flex-col gap-3">
      <div>
        <h2 className="font-semibold">
          Listening ports{" "}
          {rows.length > 0 && (
            <span className="text-muted-foreground text-sm font-normal">
              {rows.length} sockets, {exposed} on all interfaces
            </span>
          )}
        </h2>
        <FactFreshnessNote label="listeners" freshness={latest} />
        {freshness.tcp && !freshness.udp && (
          <p className="text-muted-foreground text-xs">
            UDP listeners haven&apos;t been reported yet (older agent).
          </p>
        )}
      </div>
      {rows.length > 0 && <ListenersTable rows={rows} />}
    </div>
  );
}
