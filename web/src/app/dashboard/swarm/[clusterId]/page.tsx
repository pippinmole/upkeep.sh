import { ArrowLeft, Info } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import {
  ContainerStateBadge,
  HostLink,
  WARN_BADGE,
  hostName,
} from "@/components/docker-fleet/badges";
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
import {
  type SwarmService,
  type SwarmServicePort,
  getSwarmCluster,
} from "@/lib/queries-docker-fleet";
import { formatDateTime, relativeTime } from "@/lib/time";

type Params = Promise<{ clusterId: string }>;

export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  const { clusterId } = await params;
  return { title: `Cluster ${clusterId.slice(0, 12)} · Swarm` };
}

const isJob = (mode: string | null) => mode === "replicated-job" || mode === "global-job";

function ModeCell({ s }: { s: SwarmService }) {
  if (isJob(s.mode)) {
    return (
      <span title="Job services report no completions / concurrency target yet">
        {s.mode}
        <span className="text-muted-foreground"> · no target</span>
      </span>
    );
  }
  if (s.mode === "replicated") return <>replicated · {s.replicas ?? "?"}</>;
  return <>{s.mode ?? "—"}</>;
}

function TasksCell({ s }: { s: SwarmService }) {
  if (s.runningTasks === null || s.desiredTasks === null) {
    return <span className="text-muted-foreground">not reported</span>;
  }
  const degraded = !isJob(s.mode) && s.runningTasks < s.desiredTasks;
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="tabular-nums">
        {s.runningTasks} / {s.desiredTasks}
      </span>
      {degraded && (
        <Badge variant="outline" className={WARN_BADGE}>
          degraded
        </Badge>
      )}
    </div>
  );
}

function portLabel(p: SwarmServicePort): string {
  const target = `${p.target}/${p.proto}`;
  const mode = p.publish_mode || "ingress";
  return p.published !== undefined && p.published !== null
    ? `${p.published} → ${target} (${mode})`
    : `${target} (${mode}, no fixed port)`;
}

export default async function SwarmClusterPage({ params }: { params: Params }) {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  const { clusterId } = await params;

  const cluster = await getSwarmCluster(session.user.id, clusterId);
  if (!cluster) notFound();
  const { summary, services, nodes } = cluster;
  const lockedManagers = nodes.filter((n) => n.state === "locked");

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-6 p-4 sm:p-6">
      <div>
        <Link
          href="/dashboard/swarm"
          className="text-muted-foreground hover:text-foreground inline-flex items-center gap-1 text-sm"
        >
          <ArrowLeft className="size-3.5" />
          All clusters
        </Link>
        <h1 className="mt-2 text-2xl font-bold">
          Cluster <span className="font-mono">{summary.clusterId.slice(0, 12)}</span>
        </h1>
        <p className="text-muted-foreground text-sm">
          {summary.services} service{summary.services === 1 ? "" : "s"}
          {summary.degraded > 0 && `, ${summary.degraded} degraded`} · {summary.managers} manager
          {summary.managers === 1 ? "" : "s"} and {summary.nodes} node
          {summary.nodes === 1 ? "" : "s"} with an agent ·{" "}
          {summary.confirmedAt ? (
            <>
              services last reported{" "}
              <span title={formatDateTime(summary.confirmedAt)}>
                {relativeTime(summary.confirmedAt)}
              </span>
              {summary.lastManager && ` by ${hostName(summary.lastManager)}`}
            </>
          ) : (
            "no service list from a manager yet"
          )}
        </p>
      </div>

      {lockedManagers.length > 0 && (
        <div className="flex gap-2 rounded-lg border border-amber-600/40 bg-amber-400/15 px-4 py-3 text-sm text-amber-900 dark:text-amber-200">
          <Info className="mt-0.5 size-4 shrink-0" />
          <p>
            {lockedManagers.map(hostName).join(", ")}{" "}
            {lockedManagers.length === 1 ? "is a locked manager" : "are locked managers"}{" "}
            (autolock): until unlocked, a locked manager reports no services, so what&apos;s shown
            comes from other managers or is the last known state.
          </p>
        </div>
      )}

      <div className="bg-muted/40 text-muted-foreground flex gap-2 rounded-lg border px-4 py-3 text-sm">
        <Info className="mt-0.5 size-4 shrink-0" />
        <p>
          Only nodes running an agent are listed. Tasks on worker nodes without an agent count
          towards running / desired but their containers aren&apos;t shown.
        </p>
      </div>

      <section className="flex flex-col gap-2">
        <h2 className="font-semibold">Services</h2>
        <div className="bg-card rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Service</TableHead>
                <TableHead>Image</TableHead>
                <TableHead>Mode</TableHead>
                <TableHead>Running / desired</TableHead>
                <TableHead>Published ports</TableHead>
                <TableHead>Task containers</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {services.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-muted-foreground h-20 text-center">
                    {summary.confirmedAt
                      ? "No services in this cluster."
                      : "No manager of this cluster has reported its services yet."}
                  </TableCell>
                </TableRow>
              ) : (
                services.map((s) => (
                  <TableRow key={s.serviceId}>
                    <TableCell className="align-top">
                      <div className="font-medium">{s.name}</div>
                      {s.stack && (
                        <Badge variant="outline" className="mt-1 font-normal">
                          stack {s.stack}
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="max-w-72 align-top font-mono text-xs break-all">
                      {s.image ?? <span className="text-muted-foreground font-sans">plugin</span>}
                    </TableCell>
                    <TableCell className="align-top text-sm whitespace-nowrap">
                      <ModeCell s={s} />
                    </TableCell>
                    <TableCell className="align-top">
                      <TasksCell s={s} />
                    </TableCell>
                    <TableCell className="align-top font-mono text-xs">
                      {s.ports.length === 0 ? (
                        <span className="text-muted-foreground font-sans">None</span>
                      ) : (
                        <ul className="flex flex-col gap-0.5">
                          {s.ports.map((p, i) => (
                            <li key={i} className="whitespace-nowrap">
                              {portLabel(p)}
                            </li>
                          ))}
                        </ul>
                      )}
                    </TableCell>
                    <TableCell className="align-top">
                      {s.tasks.length === 0 ? (
                        <span className="text-muted-foreground text-sm">
                          None on nodes with an agent
                        </span>
                      ) : (
                        <ul className="flex flex-col gap-1">
                          {s.tasks.map((t) => (
                            <li
                              key={`${t.hostId}:${t.containerId}`}
                              className="flex flex-wrap items-center gap-2 text-sm"
                            >
                              <HostLink
                                hostId={t.hostId}
                                hostname={t.hostname}
                                label={t.label}
                                tab="containers"
                              />
                              <span
                                className="text-muted-foreground font-mono text-xs"
                                title={t.taskId ? `Task ${t.taskId}` : undefined}
                              >
                                {t.name}
                              </span>
                              <ContainerStateBadge state={t.state} />
                            </li>
                          ))}
                        </ul>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </section>

      <section className="flex flex-col gap-2">
        <h2 className="font-semibold">Nodes with an agent</h2>
        <div className="bg-card rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Host</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Engine</TableHead>
                <TableHead className="text-right">Tasks running / seen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {nodes.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-muted-foreground h-20 text-center">
                    No host with an agent is known to be in this cluster.
                  </TableCell>
                </TableRow>
              ) : (
                nodes.map((n) => (
                  <TableRow key={n.hostId}>
                    <TableCell>
                      <HostLink
                        hostId={n.hostId}
                        hostname={n.hostname}
                        label={n.label}
                        tab="containers"
                      />
                    </TableCell>
                    <TableCell>
                      {n.role ?? <span className="text-muted-foreground">unknown</span>}
                    </TableCell>
                    <TableCell>
                      {n.state === "locked" ? (
                        <Badge variant="outline" className={WARN_BADGE}>
                          locked
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground">{n.state ?? "—"}</span>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {n.engineVersion ?? "—"}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {n.runningTasks} / {n.tasks}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </section>
    </main>
  );
}
