import { Clock, RefreshCcw } from "lucide-react";
import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { formatUptime, getHostSystem } from "@/lib/queries-host-facts";
import { formatDateTime } from "@/lib/time";

// Host header badges: architecture, uptime, and a "needs restart" pill when
// processes run deleted libraries. Renders nothing for hosts whose agent
// predates these collectors.
export async function SystemBadges({ userId, hostId }: { userId: string; hostId: string }) {
  const sys = await getHostSystem(userId, hostId);
  if (!sys) return null;
  const restart = sys.needsRestart?.processes.length ?? 0;

  return (
    <>
      {sys.arch && (
        <Badge variant="outline" className="text-muted-foreground font-mono font-normal">
          {sys.arch}
        </Badge>
      )}
      {sys.uptimeSeconds !== null && (
        <Badge
          variant="outline"
          className="text-muted-foreground gap-1 font-normal"
          title={sys.bootedAt ? `Booted ${formatDateTime(sys.bootedAt)}` : undefined}
        >
          <Clock className="size-3" />
          Up {formatUptime(sys.uptimeSeconds)}
        </Badge>
      )}
      {restart > 0 && (
        <Link href={`/dashboard/hosts/${hostId}`}>
          <Badge
            variant="outline"
            className="gap-1 border-amber-500/50 text-amber-700 dark:text-amber-400"
            title="Processes still running deleted (upgraded) shared libraries"
          >
            <RefreshCcw className="size-3" />
            {restart} {restart === 1 ? "process needs" : "processes need"} restart
          </Badge>
        </Link>
      )}
    </>
  );
}
