import { Monitor } from "lucide-react";
import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { auth } from "@/lib/auth";
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
  const session = await auth();
  if (!session?.user?.id) redirect("/login");

  const [hosts, remoteAgents] = await Promise.all([
    getHosts(session.user.id),
    getCollectorAgents(session.user.id),
  ]);
  const serverUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";
  const active = hosts.filter((h) => !h.archivedAt).length;
  const archived = hosts.length - active;

  return (
    <main className="flex min-h-0 flex-1 flex-col p-4 sm:p-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-2xl font-bold">Hosts</h1>
          <p className="text-muted-foreground text-sm">
            The machines you monitor.
            {hosts.length > 0 &&
              ` ${active} ${active === 1 ? "host" : "hosts"}${archived > 0 ? `, ${archived} archived` : ""}.`}
          </p>
        </div>
        <AddHostDialog serverUrl={serverUrl} agents={remoteAgents} />
      </div>

      <div className="mt-6">
        {hosts.length === 0 ? (
          <div className="border-border bg-card flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
            <Monitor className="text-muted-foreground size-8" />
            <div>
              <h2 className="font-semibold">No hosts yet</h2>
              <p className="text-muted-foreground mt-1 max-w-sm text-sm">
                Add a host by running the agent on it, or by letting an agent you already run reach
                it over SSH.
              </p>
            </div>
            <AddHostDialog serverUrl={serverUrl} agents={remoteAgents} />
          </div>
        ) : (
          <HostsTable hosts={hosts} />
        )}
      </div>
    </main>
  );
}
