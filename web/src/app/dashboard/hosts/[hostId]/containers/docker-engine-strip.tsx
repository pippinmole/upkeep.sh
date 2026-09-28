import { Lock } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import type { HostDockerEngine } from "@/lib/queries-docker";
import { formatDateTime, relativeTime } from "@/lib/time";

// Engine + Swarm membership (host_docker), last known values: shown under
// the Containers heading.
export function DockerEngineStrip({ engine }: { engine: HostDockerEngine }) {
  const items: { label: string; value: React.ReactNode; title?: string }[] = [];
  if (engine.engineVersion) {
    items.push({
      label: "Engine",
      value: engine.engineVersion,
      title: engine.apiVersion ? `Highest supported API version ${engine.apiVersion}` : undefined,
    });
  }
  if (engine.storageDriver || engine.imageStore) {
    items.push({
      label: "Storage",
      value: [
        engine.storageDriver,
        engine.imageStore === "containerd"
          ? "containerd image store"
          : engine.imageStore === "graphdriver"
            ? "classic image store"
            : null,
      ]
        .filter(Boolean)
        .join(", "),
    });
  }
  if (engine.rootless !== null) {
    items.push({ label: "Rootless", value: engine.rootless ? "Yes" : "No" });
  }
  let swarm: React.ReactNode = "Not in a Swarm";
  if (engine.swarmState === "locked") {
    swarm = (
      <Badge
        variant="outline"
        className="gap-1 border-amber-500/50 text-amber-700 dark:text-amber-400"
        title="Autolock is on and this manager hasn't been unlocked: the engine reports no role or cluster until it is (last known values shown if any)."
      >
        <Lock className="size-3" />
        Locked{engine.swarmRole ? ` ${engine.swarmRole}` : ""}
      </Badge>
    );
  } else if (engine.swarmState) {
    swarm = (
      <span
        title={[
          engine.swarmNodeId && `Node ${engine.swarmNodeId}`,
          engine.swarmClusterId && `Cluster ${engine.swarmClusterId}`,
        ]
          .filter(Boolean)
          .join(" · ")}
      >
        {engine.swarmRole
          ? engine.swarmRole[0].toUpperCase() + engine.swarmRole.slice(1)
          : "Member"}
        {engine.swarmState !== "active" ? ` (${engine.swarmState})` : ""}
      </span>
    );
  }
  items.push({ label: "Swarm", value: swarm });

  return (
    <div className="bg-card flex flex-wrap items-center gap-x-5 gap-y-1 rounded-lg border px-4 py-2 text-sm">
      {items.map((it) => (
        <span key={it.label} className="inline-flex items-center gap-1.5" title={it.title}>
          <span className="text-muted-foreground">{it.label}</span>
          <span className="font-medium">{it.value}</span>
        </span>
      ))}
      {engine.collectedAt && (
        <span
          className="text-muted-foreground ml-auto text-xs"
          title={formatDateTime(engine.collectedAt)}
        >
          Engine info from {relativeTime(engine.collectedAt)}
        </span>
      )}
    </div>
  );
}
