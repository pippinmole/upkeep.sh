import { Server } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { requireViewer } from "@/lib/viewer";
import { getHosts } from "@/lib/queries";
import { getCollectorAgents } from "@/lib/queries-remote";

import { AddHostDialog } from "./add-host-dialog";
import { HostsTable } from "./hosts-table";

export const metadata: Metadata = {
  title: "Hosts",
};

// The machine list (DOMAIN_MODEL.md §3.1, §4): every host of the account
// with the agent(s) collecting it. Agents (the collectors) have their own
// page. "Add host" either enrolls an agent on the machine (the same panel
// as "Register agent" there, Q15) or has an existing agent reach it over
// SSH (§4.2).
export default async function HostsPage() {
  const { workspaceId } = await requireViewer();

  const [hosts, remoteAgents] = await Promise.all([
    getHosts(workspaceId),
    getCollectorAgents(workspaceId),
  ]);
  const serverUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";
  const active = hosts.filter((h) => !h.archivedAt).length;
  const archived = hosts.length - active;
  const empty = hosts.length === 0;

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-6 p-4 sm:p-6">
      <PageHeader
        title="Hosts"
        description="The machines you monitor. Each is reported by an agent — on the machine itself or over SSH."
        meta={
          !empty && (
            <span className="tabular-nums">
              {active} {active === 1 ? "host" : "hosts"}
              {archived > 0 && ` · ${archived} archived`}
            </span>
          )
        }
        // The empty state carries the action when there are no hosts.
        actions={!empty && <AddHostDialog serverUrl={serverUrl} agents={remoteAgents} />}
      />

      {empty ? (
        <EmptyState
          icon={Server}
          size="page"
          title="No hosts yet"
          description="A host is a machine you monitor, reported by an agent. Install the agent on the machine, or let an agent you already run reach it over SSH."
          action={<AddHostDialog serverUrl={serverUrl} agents={remoteAgents} />}
          secondaryAction={
            <Button asChild variant="ghost">
              <Link href="/dashboard/agents">About agents</Link>
            </Button>
          }
        />
      ) : (
        <HostsTable hosts={hosts} />
      )}
    </main>
  );
}
