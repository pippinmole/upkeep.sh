import { RefreshCcw } from "lucide-react";
import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { formatUptime, type HostSystem } from "@/lib/queries-host-facts";
import { formatDateTime } from "@/lib/time";

// Host header, from the newest snapshot's system facts. Both render nothing
// for hosts whose agent predates these collectors.

// Status badge: processes still running deleted (upgraded) libraries.
export function RestartBadge({ sys, hostId }: { sys: HostSystem | null; hostId: string }) {
  const restart = sys?.needsRestart?.processes.length ?? 0;
  if (restart === 0) return null;
  return (
    <Link href={`/dashboard/hosts/${hostId}`}>
      <Badge variant="warning" title="Processes still running deleted (upgraded) shared libraries">
        <RefreshCcw aria-hidden />
        {restart} {restart === 1 ? "process needs" : "processes need"} restart
      </Badge>
    </Link>
  );
}

// Meta-line facts: architecture and uptime.
export function systemMeta(sys: HostSystem | null) {
  if (!sys) return [];
  const items = [];
  if (sys.arch) {
    items.push(
      <span key="arch" className="font-mono" title="Architecture">
        {sys.arch}
      </span>,
    );
  }
  if (sys.uptimeSeconds !== null) {
    items.push(
      <span
        key="uptime"
        title={sys.bootedAt ? `Booted ${formatDateTime(sys.bootedAt)}` : undefined}
      >
        Up {formatUptime(sys.uptimeSeconds)}
      </span>,
    );
  }
  return items;
}
