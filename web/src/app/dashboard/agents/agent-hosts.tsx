import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { KevBadge, SeverityBadge } from "@/components/vuln/badges";
import type { AgentHostRow, AgentWithHosts } from "@/lib/queries";
import { relativeTime } from "@/lib/time";

import { DetachHostButton } from "./detach-host-button";

const MODE_LABEL: Record<AgentHostRow["mode"], string> = {
  local: "Local",
  ssh: "SSH",
  winrm: "WinRM",
};

export function osLabel(h: Pick<AgentHostRow, "osId" | "osVersion" | "osCodename">): string {
  if (!h.osId) return "—";
  const name = h.osId.charAt(0).toUpperCase() + h.osId.slice(1);
  const version = [h.osVersion, h.osCodename && `(${h.osCodename})`].filter(Boolean).join(" ");
  return version ? `${name} ${version}` : name;
}

// The expanded part of an agent row: the hosts it collects. A host can be
// listed under two agents (e.g. after a reinstall re-attached it by
// identity); each listing is that agent's assignment.
export function AgentHosts({ agent }: { agent: AgentWithHosts }) {
  if (agent.hosts.length === 0) {
    return (
      <p className="text-muted-foreground px-12 py-3 text-sm">
        {agent.status === "revoked"
          ? "Revoked before its first push; no hosts."
          : "Waiting for first push. The host appears here once the agent reports in."}
      </p>
    );
  }

  return (
    <div className="overflow-x-auto px-4 py-2 sm:pl-12">
      <table className="w-full text-sm">
        <thead className="text-muted-foreground text-left text-xs">
          <tr>
            <th className="py-1.5 pr-4 font-medium">Host</th>
            <th className="py-1.5 pr-4 font-medium">OS</th>
            <th className="py-1.5 pr-4 font-medium">Mode</th>
            <th className="py-1.5 pr-4 font-medium">Last collected</th>
            <th className="py-1.5 pr-4 font-medium">Open findings</th>
            <th className="py-1.5 font-medium">
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {agent.hosts.map((h) => (
            <tr key={h.hostId} className="border-border/60 border-t">
              <td className="py-2 pr-4">
                <div className="flex flex-wrap items-center gap-1.5">
                  <Link
                    href={`/dashboard/hosts/${h.hostId}`}
                    className="font-medium hover:underline"
                  >
                    {h.hostname}
                  </Link>
                  {h.label && <span className="text-muted-foreground">{h.label}</span>}
                  {h.duplicateOf && (
                    <Link
                      href={`/dashboard/hosts/${h.duplicateOf}`}
                      title="Same machine identity as another host"
                    >
                      <Badge
                        variant="outline"
                        className="border-amber-600/50 text-amber-800 dark:text-amber-200"
                      >
                        Possible duplicate
                      </Badge>
                    </Link>
                  )}
                  {!h.enabled && <Badge variant="outline">Disabled</Badge>}
                  {h.archivedAt && (
                    <Badge variant="outline" className="text-muted-foreground">
                      {h.mergedInto ? "Merged" : "Archived"}
                    </Badge>
                  )}
                </div>
              </td>
              <td className="text-muted-foreground py-2 pr-4 whitespace-nowrap">{osLabel(h)}</td>
              <td className="py-2 pr-4">
                <span className="text-muted-foreground">{MODE_LABEL[h.mode]}</span>
                {h.mode !== "local" && (
                  <span className="text-muted-foreground/70 ml-1 font-mono text-xs">
                    {h.targetRef}
                  </span>
                )}
              </td>
              <td className="text-muted-foreground py-2 pr-4 whitespace-nowrap">
                {h.lastCollectedAt ? relativeTime(h.lastCollectedAt) : "Not yet"}
              </td>
              <td className="py-2 pr-4">
                <Findings host={h} />
              </td>
              <td className="py-2 text-right">
                {/* Only an inactive agent's assignment can be detached; an
                    active agent's next push would re-attach it. */}
                {(agent.status === "revoked" || agent.status === "stale") && (
                  <DetachHostButton agent={agent} host={h} />
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Findings({ host }: { host: AgentHostRow }) {
  if (host.openFindings === 0) return <span className="text-muted-foreground">0</span>;
  const pills = (
    <span className="inline-flex flex-wrap items-center gap-1">
      <span className="mr-0.5 font-medium tabular-nums">{host.openFindings}</span>
      {host.topSeverity && <SeverityBadge severity={host.topSeverity} />}
      {host.kevVulns > 0 && <KevBadge count={host.kevVulns} />}
    </span>
  );
  return host.openVulns > 0 ? (
    <Link href={`/dashboard/hosts/${host.hostId}/vulnerabilities`} title="Open vulnerabilities">
      {pills}
    </Link>
  ) : (
    pills
  );
}
