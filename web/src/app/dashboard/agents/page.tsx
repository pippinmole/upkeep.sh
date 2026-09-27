import { Server } from "lucide-react";
import type { Metadata } from "next";
import { redirect } from "next/navigation";

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

  return (
    <main className="flex min-h-0 flex-1 flex-col p-4 sm:p-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-2xl font-bold">Agents</h1>
          <p className="text-muted-foreground text-sm">
            Monitoring agents and the hosts they collect.
            {agents.length > 0 &&
              ` ${agents.length} ${agents.length === 1 ? "agent" : "agents"}, ${hostCount} ${hostCount === 1 ? "host" : "hosts"}.`}
          </p>
        </div>
        <RegisterAgentDialog serverUrl={serverUrl} />
      </div>

      <div className="mt-6">
        {agents.length === 0 ? (
          <div className="border-border bg-card flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
            <Server className="text-muted-foreground size-8" />
            <div>
              <h2 className="font-semibold">No agents registered yet</h2>
              <p className="text-muted-foreground mt-1 max-w-sm text-sm">
                Register your first agent to start monitoring a host. You&apos;ll get a one-time
                token and a docker command to run on that machine.
              </p>
            </div>
            <RegisterAgentDialog serverUrl={serverUrl} />
          </div>
        ) : (
          <AgentsTable agents={agents} />
        )}
      </div>
    </main>
  );
}
