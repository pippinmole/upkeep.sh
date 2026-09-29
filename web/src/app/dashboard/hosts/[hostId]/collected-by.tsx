import { Network } from "lucide-react";
import Link from "next/link";
import { Fragment } from "react";

import { Badge } from "@/components/ui/badge";
import type { HostCollector } from "@/lib/queries-remote";
import { cn } from "@/lib/utils";

const REMOTE_LABEL: Record<string, string> = { ssh: "Remote (SSH)", winrm: "Remote (WinRM)" };

// Host header meta: which agents collect this host, with a "Remote (SSH)"
// badge on agents that reach it over SSH. Those can only read files, so
// Docker, listening ports, port exposure and live process state are missing
// (docs/tasks/phase-1-6-docker-exposure.md); the badge's title says so.
export function CollectedBy({ agents }: { agents: HostCollector[] }) {
  if (agents.length === 0) return null;

  return (
    <span className="inline-flex flex-wrap items-center gap-x-1.5 gap-y-1">
      <span>Collected by</span>
      {agents.map((a, i) => {
        const remote = a.mode !== "local";
        return (
          <Fragment key={a.id}>
            <span className="inline-flex items-center gap-1.5">
              <Link
                href="/dashboard/agents"
                className={cn(
                  "text-foreground hover:underline",
                  a.status === "revoked" && "text-muted-foreground line-through",
                )}
              >
                {a.name}
              </Link>
              {remote && (
                <Badge
                  variant="outline"
                  className="text-muted-foreground font-normal"
                  title={`${a.name} reads this host over ${a.mode.toUpperCase()} and can only read files: Docker containers and images, listening ports, port exposure, processes needing a restart and service running state aren't collected. Install the agent on this host for those.`}
                >
                  <Network aria-hidden />
                  {REMOTE_LABEL[a.mode] ?? `Remote (${a.mode})`}
                </Badge>
              )}
            </span>
            {i < agents.length - 1 && <span className="-ml-1.5">,</span>}
          </Fragment>
        );
      })}
    </span>
  );
}
