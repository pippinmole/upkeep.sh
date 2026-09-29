import { Boxes } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { HostLink } from "@/components/docker-fleet/badges";
import { DockerCoverageNote } from "@/components/docker-fleet/coverage-note";
import { EmptyState } from "@/components/empty-state";
import { PageHeader, SectionHeading } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { auth } from "@/lib/auth";
import {
  getDockerCoverage,
  getSwarmClusters,
  getUnattributedSwarmHosts,
} from "@/lib/queries-docker-fleet";
import { formatDateTime, relativeTime } from "@/lib/time";

export const metadata: Metadata = {
  title: "Swarm",
};

export default async function SwarmClustersPage() {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  const userId = session.user.id;

  const [clusters, unattributed, coverage] = await Promise.all([
    getSwarmClusters(userId),
    getUnattributedSwarmHosts(userId),
    getDockerCoverage(userId),
  ]);

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-6 p-4 sm:p-6">
      <PageHeader
        title="Swarm"
        description={
          <>
            {clusters.length > 0 &&
              `${clusters.length} ${clusters.length === 1 ? "cluster" : "clusters"}. `}
            Docker Swarm clusters your hosts belong to. Services come from the managers; task
            containers from every node that runs an agent.
          </>
        }
      />

      <DockerCoverageNote coverage={coverage} />

      {clusters.length === 0 ? (
        <EmptyState
          size="page"
          icon={Boxes}
          title="No Swarm clusters yet"
          description="None of your hosts has reported being a Swarm manager. Services are read from a manager node, so install an agent with Docker collection enabled on one."
          action={
            <Button asChild>
              <Link href="/dashboard/agents">Install an agent</Link>
            </Button>
          }
        />
      ) : (
        <div className="bg-card rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Cluster</TableHead>
                <TableHead className="text-right">Services</TableHead>
                <TableHead className="text-right">Managers</TableHead>
                <TableHead className="text-right">Nodes with an agent</TableHead>
                <TableHead>Services last reported</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {clusters.map((c) => (
                <TableRow key={c.clusterId}>
                  <TableCell>
                    <Link
                      href={`/dashboard/swarm/${c.clusterId}`}
                      className="font-mono text-sm font-medium hover:underline"
                      title={c.clusterId}
                    >
                      {c.clusterId.slice(0, 12)}
                    </Link>
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-2">
                      {c.degraded > 0 && (
                        <Badge variant="warning" className="font-normal">
                          {c.degraded} degraded
                        </Badge>
                      )}
                      <span className="tabular-nums">{c.services}</span>
                    </div>
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-2">
                      {c.lockedManagers > 0 && (
                        <Badge variant="warning" className="font-normal">
                          {c.lockedManagers} locked
                        </Badge>
                      )}
                      <span className="tabular-nums">{c.managers}</span>
                    </div>
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{c.nodes}</TableCell>
                  <TableCell className="text-muted-foreground whitespace-nowrap">
                    {c.confirmedAt ? (
                      <>
                        <span title={formatDateTime(c.confirmedAt)}>
                          {relativeTime(c.confirmedAt)}
                        </span>
                        {c.lastManager && (
                          <>
                            {" by "}
                            <HostLink {...c.lastManager} />
                          </>
                        )}
                      </>
                    ) : (
                      "Not yet"
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {unattributed.length > 0 && (
        <section className="flex flex-col gap-2">
          <SectionHeading description="Docker doesn't tell worker nodes which cluster they're in, so a worker shows up under its cluster only once it runs a task of a service a manager reported.">
            Swarm members not placed in a cluster
          </SectionHeading>
          <div className="bg-card rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Host</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>State</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {unattributed.map((h) => (
                  <TableRow key={h.hostId}>
                    <TableCell>
                      <HostLink hostId={h.hostId} hostname={h.hostname} label={h.label} />
                    </TableCell>
                    <TableCell className="text-muted-foreground">{h.role ?? "unknown"}</TableCell>
                    <TableCell>
                      {h.state === "locked" ? (
                        <Badge variant="warning" className="font-normal">
                          locked
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground">{h.state}</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </section>
      )}
    </main>
  );
}
