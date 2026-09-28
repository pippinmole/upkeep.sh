import { Network } from "lucide-react";
import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { getHostCollectors } from "@/lib/queries-remote";

const REMOTE_LABEL: Record<string, string> = { ssh: "Remote (SSH)", winrm: "Remote (WinRM)" };

// Host header: which agents collect this host, with a "Remote (SSH)" badge
// on agents that reach it over SSH. Those can only read files, so Docker,
// listening ports, port exposure and live process state are missing
// (docs/tasks/phase-1-6-docker-exposure.md); the badge's title says so.
export async function CollectedBy({ userId, hostId }: { userId: string; hostId: string }) {
  const agents = await getHostCollectors(userId, hostId);
  if (agents.length === 0) return null;

  return (
    <div className="text-muted-foreground mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
      <span>Collected by</span>
      {agents.map((a) => {
        const remote = a.mode !== "local";
        return (
          <span key={a.id} className="inline-flex items-center gap-1.5">
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
                className="text-muted-foreground gap-1 font-normal"
                title={`${a.name} reads this host over ${a.mode.toUpperCase()} and can only read files: Docker containers and images, listening ports, port exposure, processes needing a restart and service running state aren't collected. Install the agent on this host for those.`}
              >
                <Network className="size-3" />
                {REMOTE_LABEL[a.mode] ?? `Remote (${a.mode})`}
              </Badge>
            )}
          </span>
        );
      })}
    </div>
  );
}
