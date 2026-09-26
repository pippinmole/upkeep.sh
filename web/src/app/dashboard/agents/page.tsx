import { Server } from "lucide-react";
import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { auth } from "@/lib/auth";
import { getHostsForUser } from "@/lib/queries";
import { relativeTime } from "@/lib/time";

import { RegisterAgentDialog } from "./register-agent-dialog";

export const metadata: Metadata = {
  title: "Agents",
};

export default async function AgentsPage() {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");

  const hosts = await getHostsForUser(session.user.id);

  // Same source of truth the docker-compose.dev/prod stacks use to tell
  // the browser bundle where the API lives; the agent needs the same URL.
  const serverUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

  return (
    <main className="flex min-h-0 flex-1 flex-col p-4 sm:p-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-2xl font-bold">Agents</h1>
          <p className="text-muted-foreground text-sm">
            Hosts reporting into this account via the monitoring agent.
          </p>
        </div>
        <RegisterAgentDialog serverUrl={serverUrl} />
      </div>

      <div className="mt-6">
        {hosts.length === 0 ? (
          <div className="border-border bg-card flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
            <Server className="text-muted-foreground size-8" />
            <div>
              <h2 className="font-semibold">No agents registered yet</h2>
              <p className="text-muted-foreground mt-1 max-w-sm text-sm">
                Register your first agent to start monitoring a host. You'll
                get a one-time token and a docker command to run on that
                machine.
              </p>
            </div>
            <RegisterAgentDialog serverUrl={serverUrl} />
          </div>
        ) : (
          <div className="border-border bg-card rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Hostname</TableHead>
                  <TableHead>Label</TableHead>
                  <TableHead>Public IP</TableHead>
                  <TableHead>Last seen</TableHead>
                  <TableHead>Open findings</TableHead>
                  <TableHead className="text-right">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {hosts.map((host) => (
                  <TableRow key={host.id}>
                    <TableCell className="font-medium">
                      {host.hostname}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {host.label ?? "—"}
                    </TableCell>
                    <TableCell className="text-muted-foreground font-mono text-xs">
                      {host.publicIpv4 || host.publicIpv6 ? (
                        <div className="flex flex-col gap-0.5">
                          {host.publicIpv4 && <span>{host.publicIpv4}</span>}
                          {host.publicIpv6 && <span>{host.publicIpv6}</span>}
                        </div>
                      ) : (
                        "—"
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {relativeTime(host.lastSeenAt)}
                    </TableCell>
                    <TableCell>
                      {host.openFindings > 0 ? (
                        <Badge variant="destructive">
                          {host.openFindings}
                        </Badge>
                      ) : (
                        <Badge variant="secondary">0</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      {/* TODO: online/offline status needs more than a raw
                          last-seen timestamp (a liveness threshold, agent
                          revocation, etc.) — not part of this pass. */}
                      <Badge variant="outline" className="text-muted-foreground">
                        Coming soon
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </main>
  );
}
