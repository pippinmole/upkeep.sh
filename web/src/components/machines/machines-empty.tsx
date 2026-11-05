import { Server } from "lucide-react";

import { AddHostDialog } from "@/app/dashboard/hosts/add-host-dialog";
import { AutoRefresh } from "@/components/auto-refresh";
import { EmptyState } from "@/components/empty-state";
import type { CollectorAgent } from "@/lib/queries-remote";

// No machine and no agent yet: the list area is one panel built around
// Add machine (members, who can't add, just read the copy).
export function MachinesEmpty({
  serverUrl,
  agents,
}: {
  serverUrl: string;
  agents: CollectorAgent[];
}) {
  return (
    <EmptyState
      icon={Server}
      size="page"
      title="Add your first machine"
      description="Install the agent on the machine, or have an agent you already run scan it over SSH. It reports within a minute."
      action={<AddHostDialog serverUrl={serverUrl} agents={agents} />}
    />
  );
}

// An agent is enrolled but no machine exists yet: its first report creates
// one. The page refreshes itself until it arrives.
export function WaitingForMachines() {
  return (
    <>
      <AutoRefresh />
      <EmptyState
        size="page"
        loading
        title="Waiting for first report"
        description="Agents report within a minute of starting. This page updates by itself when the first machine arrives."
      />
    </>
  );
}
