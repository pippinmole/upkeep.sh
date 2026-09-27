import { Monitor } from "lucide-react";
import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { auth } from "@/lib/auth";
import { getHosts } from "@/lib/queries";

import { RegisterAgentDialog } from "../agents/register-agent-dialog";
import { HostsTable } from "./hosts-table";

export const metadata: Metadata = {
  title: "Hosts",
};

// The machine list (DOMAIN_MODEL.md §3.1, §4): every host of the account
// with the agent(s) collecting it. Agents (the collectors) have their own
// page; "Add host" here and "Register agent" there open the same dialog
// (Q15), since adding a host means enrolling an agent on it.
export default async function HostsPage() {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");

  const hosts = await getHosts(session.user.id);
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
        <RegisterAgentDialog serverUrl={serverUrl} triggerLabel="Add host" />
      </div>

      <div className="mt-6">
        {hosts.length === 0 ? (
          <div className="border-border bg-card flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
            <Monitor className="text-muted-foreground size-8" />
            <div>
              <h2 className="font-semibold">No hosts yet</h2>
              <p className="text-muted-foreground mt-1 max-w-sm text-sm">
                Add a host by running the agent on it. You&apos;ll get a one-time token and a docker
                command; the host appears here after the agent&apos;s first push.
              </p>
            </div>
            <RegisterAgentDialog serverUrl={serverUrl} triggerLabel="Add host" />
          </div>
        ) : (
          <HostsTable hosts={hosts} />
        )}
      </div>
    </main>
  );
}
