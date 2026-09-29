import Link from "next/link";

import { OsLogo } from "@/components/brand";
import { Badge } from "@/components/ui/badge";
import { KevBadge, SeverityBadge } from "@/components/vuln/badges";
import { osLabel as osNameVersion } from "@/lib/os";
import type { AgentHostRow, AgentWithHosts } from "@/lib/queries";

import { TimeAgo } from "../hosts/table-cells";
import { DetachHostButton } from "./detach-host-button";

const MODE_LABEL: Record<AgentHostRow["mode"], string> = {
  local: "Local",
  ssh: "SSH",
  winrm: "WinRM",
};

function osLabel(h: Pick<AgentHostRow, "osId" | "osVersion" | "osCodename">): string {
  if (!h.osId) return "—";
  const codename = h.osCodename ? ` (${h.osCodename})` : "";
  return `${osNameVersion(h.osId, h.osVersion)}${codename}`;
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
            <th className="py-1.5 pr-4 text-right font-medium">Open findings</th>
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
                  <OsLogo osId={h.osId} size={16} className="text-muted-foreground" />
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
                      <Badge variant="warning">Possible duplicate</Badge>
                    </Link>
                  )}
                  {!h.enabled && <Badge variant="dashed">Disabled</Badge>}
                  {h.archivedAt && (
                    <Badge variant="neutral">{h.mergedInto ? "Merged" : "Archived"}</Badge>
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
              <td className="py-2 pr-4">
                <TimeAgo
                  iso={h.lastCollectedAt}
                  fallback="Not yet"
                  className="text-muted-foreground"
                />
              </td>
              <td className="py-2 pr-4 text-right tabular-nums">
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
    <span className="inline-flex flex-wrap items-center justify-end gap-1">
      {host.topSeverity && <SeverityBadge severity={host.topSeverity} />}
      {host.kevVulns > 0 && <KevBadge count={host.kevVulns} />}
      <span className="ml-0.5 font-medium">{host.openFindings}</span>
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
