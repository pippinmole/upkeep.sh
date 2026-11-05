import type { Metadata } from "next";
import { Suspense } from "react";

import { AutoRefresh } from "@/components/auto-refresh";
import { PageHeader } from "@/components/layout/page-header";
import { MachineList } from "@/components/machines/machine-list";
import { MachinesEmpty, WaitingForMachines } from "@/components/machines/machines-empty";
import { machinesSummaryText, summarizeMachines } from "@/lib/machines";
import { getMachines } from "@/lib/queries-machines";
import { getOnboardingState } from "@/lib/queries-onboarding";
import { getCollectorAgents } from "@/lib/queries-remote";
import { requireViewer } from "@/lib/viewer";

import { AddHostDialog } from "./hosts/add-host-dialog";

export const metadata: Metadata = {
  title: "Machines",
};

// The dashboard home: every machine of the workspace, alphabetical, with its
// open vulnerabilities (spec 2026-11-05 §6.2). Host package and container
// image counts stay apart (DOMAIN_MODEL.md §3.6). Search and filters live in
// the URL and run on the client over these rows (MachineList reads them); if workspaces grow large,
// push them into SQL.
export default async function MachinesPage() {
  const { workspaceId } = await requireViewer();
  const [rows, agents, onboarding] = await Promise.all([
    getMachines(workspaceId),
    getCollectorAgents(workspaceId),
    getOnboardingState(workspaceId),
  ]);
  const serverUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";
  const empty = rows.length === 0;
  const firstRun = empty && !onboarding.agent;

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-6 p-4 sm:p-6">
      <PageHeader
        title="Machines"
        meta={
          !empty && (
            <span className="tabular-nums">{machinesSummaryText(summarizeMachines(rows))}</span>
          )
        }
        // The first-run panel carries its own Add machine button.
        actions={!firstRun && <AddHostDialog serverUrl={serverUrl} agents={agents} />}
      />

      {firstRun ? (
        <MachinesEmpty serverUrl={serverUrl} agents={agents} />
      ) : empty ? (
        <WaitingForMachines />
      ) : (
        <>
          {/* Quick while waiting for the first report, then once a minute. */}
          <AutoRefresh everyMs={onboarding.hostReported ? 60_000 : 10_000} />
          <Suspense fallback={null}>
            <MachineList rows={rows} />
          </Suspense>
        </>
      )}
    </main>
  );
}
