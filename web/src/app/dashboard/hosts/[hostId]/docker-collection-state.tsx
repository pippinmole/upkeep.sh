import { AlertTriangle, Boxes, Network, PlugZap, type LucideIcon } from "lucide-react";

import { RegisterAgentDialog } from "@/app/dashboard/agents/register-agent-dialog";
import {
  DOCKER_SOCKET_MOUNT,
  DockerSocketAlternatives,
  DockerSocketGrant,
} from "@/components/docker-socket-notes";
import { EmptyState } from "@/components/empty-state";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { dockerCollection, type DockerFreshness } from "@/lib/queries-docker";
import type { CollectorStatus } from "@/lib/queries-inventory";
import { getHostCollectors, type HostCollector } from "@/lib/queries-remote";
import { formatDateTime, relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";

type What = "containers" | "images";

// Why a host's Containers / Images tab is empty, or why its rows may be out
// of date (docs/tasks/phase-1-6-docker-exposure.md
// "Docker is collected only on hosts with their own agent"). Keyed on the
// newest snapshot's collector_status, never on
// "no rows": stored rows stay as last known after collection stops.
//
// - hasRows false: the whole empty state (remote / not enabled / engine
//   unreachable / collector failed / not reported / a normal empty list).
// - hasRows true and collection not ok: a banner above the (stale) table.
// - hasRows true and ok: nothing.
export async function DockerCollectionState({
  userId,
  hostId,
  what,
  collectorStatus,
  freshness,
  hasRows,
}: {
  userId: string;
  hostId: string;
  what: What;
  collectorStatus: Record<string, CollectorStatus> | null | undefined;
  freshness: DockerFreshness;
  hasRows: boolean;
}) {
  const agents = await getHostCollectors(userId, hostId);
  const active = agents.filter((a) => a.status !== "revoked");
  const onlyRemote = active.length > 0 && active.every((a) => a.mode !== "local");
  const state = dockerCollection(
    collectorStatus,
    what === "containers" ? "docker_containers" : "docker_images",
    onlyRemote,
  );
  if (state.kind === "ok" && hasRows) {
    return state.truncated ? (
      <p className="text-muted-foreground text-xs">
        The agent hit a size cap in the latest snapshot, so this list may be incomplete (entries are
        only added, not removed, until a complete list arrives).
      </p>
    ) : null;
  }

  const content = describe(state, what, active);
  const stale =
    hasRows && freshness ? (
      <p className="mt-1">
        Showing the {what} last collected{" "}
        <span title={formatDateTime(freshness.confirmedAt)}>
          {relativeTime(freshness.confirmedAt)}
        </span>{" "}
        ({formatDateTime(freshness.confirmedAt)}), which may be out of date.
      </p>
    ) : null;

  if (hasRows) {
    return (
      <Alert>
        <content.icon className={cn(content.warn && "text-warning-fg!", "size-4")} />
        <AlertTitle>{content.title}</AlertTitle>
        <AlertDescription className="text-muted-foreground">
          {content.body}
          {stale}
        </AlertDescription>
      </Alert>
    );
  }

  // Server URL for the agent install command, as on the Agents page.
  const serverUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";
  return (
    <EmptyState
      icon={content.icon}
      title={content.title}
      description={content.body}
      variant={content.warn ? "warning" : state.kind === "not_enabled" ? "info" : "default"}
      action={
        state.kind === "remote" && (
          <RegisterAgentDialog
            serverUrl={serverUrl}
            triggerLabel="Install the agent on this host"
            triggerVariant="outline"
            defaultWithDocker
          />
        )
      }
    />
  );
}

function agentNames(agents: HostCollector[], remote: boolean) {
  const names = agents.filter((a) => (a.mode !== "local") === remote).map((a) => a.name);
  return names.length ? names.join(", ") : null;
}

function describe(
  state: ReturnType<typeof dockerCollection>,
  what: What,
  agents: HostCollector[],
): { icon: LucideIcon; title: string; body: React.ReactNode; warn?: boolean } {
  switch (state.kind) {
    case "remote": {
      const by = agentNames(agents, true) ?? "another agent";
      const mode = agents.find((a) => a.mode !== "local")?.mode ?? "ssh";
      return {
        icon: Network,
        title: "Docker data needs an agent on this host",
        body: (
          <>
            This host is collected over {mode.toUpperCase()} by{" "}
            <span className="text-foreground font-medium">{by}</span>, which can only read files.
            Install the agent on the host itself, with Docker collection enabled, to see its
            containers and images.
          </>
        ),
      };
    }
    case "not_enabled": {
      const by = agentNames(agents, false);
      return {
        icon: PlugZap,
        title: "Docker collection isn't enabled on this agent",
        body: (
          <div className="flex flex-col items-center gap-2">
            <p>
              {by ? (
                <>
                  <span className="text-foreground font-medium">{by}</span> has
                </>
              ) : (
                "The agent has"
              )}{" "}
              no Docker socket mounted. To collect containers and images, add this mount to the
              agent&apos;s container and re-create it:
            </p>
            <pre className="bg-muted text-foreground w-fit max-w-full overflow-x-auto rounded-md border px-3 py-2 text-left text-xs">
              {DOCKER_SOCKET_MOUNT}
            </pre>
            <p className="text-xs">
              (Compose: <code>- /var/run/docker.sock:/var/run/docker.sock</code> under{" "}
              <code>volumes:</code>.) <DockerSocketGrant />
            </p>
            <DockerSocketAlternatives />
          </div>
        ),
      };
    }
    case "engine_unavailable":
      return {
        icon: AlertTriangle,
        warn: true,
        title: "The Docker engine isn't reachable",
        body: (
          <div className="flex flex-col items-center gap-2">
            <p>
              The agent has a Docker socket mounted but couldn&apos;t use it in the latest snapshot
              {state.error ? ":" : "."}
            </p>
            {state.error && (
              <pre className="bg-muted text-foreground w-fit max-w-full overflow-x-auto rounded-md border px-3 py-2 text-left text-xs whitespace-pre-wrap">
                {state.error}
              </pre>
            )}
            <p className="text-xs">
              Common causes: the engine isn&apos;t running, the socket isn&apos;t owned by root (add{" "}
              <code>--group-add</code> with the socket&apos;s group id), or the engine is older than
              API version 1.41.
            </p>
          </div>
        ),
      };
    case "error":
      return {
        icon: AlertTriangle,
        warn: true,
        title: `Couldn't collect ${what} in the latest snapshot`,
        body: (
          <>
            The Docker {what} collector failed{state.error ? `: ${state.error}` : "."} Nothing from
            that run was applied.
          </>
        ),
      };
    case "skipped":
      return {
        icon: Boxes,
        title: `Docker ${what} weren't collected`,
        body: `The collector was skipped in the latest snapshot${state.reason ? ` (${state.reason})` : ""}.`,
      };
    case "not_reported":
      return {
        icon: Boxes,
        title: "No Docker data reported",
        body: "The agent collecting this host hasn't reported Docker collection. It needs an agent version with the Docker collectors; update the agent, and enable Docker collection if it isn't.",
      };
    case "ok":
      return what === "containers"
        ? {
            icon: Boxes,
            title: "No containers",
            body: "The Docker engine on this host has no containers, running or stopped.",
          }
        : {
            icon: Boxes,
            title: "No images",
            body: "The Docker engine on this host has no images.",
          };
  }
}
