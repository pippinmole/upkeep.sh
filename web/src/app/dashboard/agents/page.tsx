import { ArrowRight, RadioTower, Server } from "lucide-react";
import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/layout/page-header";
import { auth } from "@/lib/auth";
import { getAgentsWithHosts } from "@/lib/queries";

import { AgentsTable } from "./agents-table";
import { RegisterAgentDialog } from "./register-agent-dialog";

export const metadata: Metadata = {
  title: "Agents",
};

// Agents, each with the hosts it collects underneath (DOMAIN_MODEL.md §4).
// The machine list is /dashboard/hosts; both pages open the same
// enrollment dialog (Q15).
export default async function AgentsPage() {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");

  const agents = await getAgentsWithHosts(session.user.id);

  // Same source of truth the docker-compose.dev/prod stacks use to tell
  // the browser bundle where the API lives; the agent needs the same URL.
  const serverUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";
  const hostCount = new Set(agents.flatMap((a) => a.hosts.map((h) => h.hostId))).size;
  const empty = agents.length === 0;

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-6 p-4 sm:p-6">
      <PageHeader
        title="Agents"
        description="Collectors that report on your hosts. An agent reports its own machine and any machines it reaches over SSH."
        meta={
          !empty && (
            <span className="tabular-nums">
              {agents.length} {agents.length === 1 ? "agent" : "agents"} · {hostCount}{" "}
              {hostCount === 1 ? "host" : "hosts"}
            </span>
          )
        }
        actions={
          !empty && <RegisterAgentDialog serverUrl={serverUrl} triggerLabel="Install an agent" />
        }
      />

      {empty ? (
        <EmptyState
          icon={RadioTower}
          size="page"
          title="No agents yet"
          description="Install the agent on a machine you want to monitor. You get a one-time token and a command to run there; the machine then shows up as a host."
          action={<RegisterAgentDialog serverUrl={serverUrl} triggerLabel="Install an agent" />}
        >
          <AgentToHost />
        </EmptyState>
      ) : (
        <AgentsTable agents={agents} />
      )}
    </main>
  );
}

// "Agent ─▶ Host(s)": what an agent is for, at a glance.
function AgentToHost() {
  return (
    <p className="text-muted-foreground flex items-center gap-2 text-xs font-medium">
      <span className="inline-flex items-center gap-1">
        <RadioTower className="size-3.5" aria-hidden />
        Agent
      </span>
      <ArrowRight className="size-3.5" aria-label="reports" />
      <span className="inline-flex items-center gap-1">
        <Server className="size-3.5" aria-hidden />
        Host(s)
      </span>
    </p>
  );
}
