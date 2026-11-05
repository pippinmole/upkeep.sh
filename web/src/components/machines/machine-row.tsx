import { RotateCw } from "lucide-react";
import Link from "next/link";
import { Children } from "react";

import { TimeAgo } from "@/components/time-ago";
import { StatusDot, type Tone } from "@/components/status";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
  collectorLabel,
  hasNoActiveAgent,
  imageVulnsTitle,
  type MachineRow as Machine,
  type MachineStatus,
  machineStatus,
} from "@/lib/machines";
import { osLabel } from "@/lib/os";
import { cn } from "@/lib/utils";

import { CountPills } from "./count-pills";
import { MachineRowMenu } from "./machine-row-menu";

const STATUS: Record<MachineStatus, { tone: Tone; label: string }> = {
  online: { tone: "success", label: "Online" },
  stale: { tone: "warning", label: "Stale" },
  never: { tone: "neutral", label: "Never reported" },
};

// Shared cell padding; below md the row is a card and the cells are its
// lines, placed on a 3-column grid (name + menu, OS + last seen, counts).
const CELL = "min-w-0 px-3 py-2.5 align-middle max-md:p-0";

// One machine, as a table row on md+ and a stacked card below. The whole
// row opens the machine: the name's link stretches over it (after:inset-0
// on the relative row); anything else clickable sits above it with
// relative z-10.
export function MachineRow({ machine: m }: { machine: Machine }) {
  return (
    <tr
      className={cn(
        "group/row hover:bg-muted/40 relative border-b transition-colors last:border-0",
        "max-md:bg-card max-md:grid max-md:grid-cols-[auto_minmax(0,1fr)_auto] max-md:gap-x-3 max-md:gap-y-1.5 max-md:rounded-lg max-md:border max-md:p-3 max-md:last:border",
        m.archivedAt && "text-muted-foreground",
      )}
    >
      <td className={cn(CELL, "max-md:col-span-2")}>
        <MachineCell machine={m} />
      </td>
      <td className={cn(CELL, "text-muted-foreground whitespace-nowrap max-md:text-sm")}>
        {osLabel(m.osId, m.osVersion) ?? "—"}
      </td>
      <td className={cn(CELL, "text-muted-foreground max-md:col-span-2 max-md:text-sm")}>
        <span className="md:hidden">Seen </span>
        <TimeAgo iso={m.lastSeenAt} />
      </td>
      <td className={cn(CELL, "max-md:col-span-3 max-md:pt-1")}>
        <VulnsCell machine={m} />
      </td>
      <td className={cn(CELL, "w-0 text-right max-md:col-start-3 max-md:row-start-1")}>
        <MachineRowMenu machine={m} />
      </td>
    </tr>
  );
}

function MachineCell({ machine: m }: { machine: Machine }) {
  const status = STATUS[machineStatus(m.agents)];
  const collector = collectorLabel(m.agents);
  const archived = m.archivedAt !== null;
  return (
    <div className="flex min-w-0 items-start gap-2.5">
      <StatusDot tone={status.tone} label={status.label} className="mt-[0.4rem]" />
      <div className="flex min-w-0 flex-col gap-0.5">
        <Link
          href={`/dashboard/hosts/${m.id}`}
          className="focus-visible:ring-ring min-w-0 truncate font-medium outline-none after:absolute after:inset-0 after:rounded-[inherit] focus-visible:after:ring-2"
        >
          {m.label ?? m.hostname}
          {m.label && (
            <span className="text-muted-foreground ml-1.5 font-normal">{m.hostname}</span>
          )}
        </Link>
        {(m.ip || collector) && (
          <span className="text-muted-foreground flex flex-wrap gap-x-2 text-xs">
            {m.ip && <span className="font-mono tabular-nums">{m.ip}</span>}
            {collector && (
              <span>
                {collector.text}
                {collector.more > 0 && <span className="tabular-nums"> +{collector.more}</span>}
              </span>
            )}
          </span>
        )}
        <Tags>
          {m.duplicateOf && !archived && (
            <Badge variant="warning" title={`Same machine identity as ${m.duplicateOf.hostname}`}>
              Possible duplicate
            </Badge>
          )}
          {m.mergedInto ? (
            <Badge variant="neutral" className="max-w-full min-w-0">
              <span className="truncate">Merged into {m.mergedInto.hostname}</span>
            </Badge>
          ) : (
            archived && <Badge variant="neutral">Archived</Badge>
          )}
          {m.rebootRequired && !archived && (
            <Badge variant="warning" title="The latest snapshot reports a pending reboot">
              <RotateCw aria-hidden />
              Reboot required
            </Badge>
          )}
          {hasNoActiveAgent(m.agents) && (
            <Badge variant="neutral" title="Every agent that collected it was revoked">
              No active agent
            </Badge>
          )}
        </Tags>
      </div>
    </div>
  );
}

// Renders nothing when no tag applies, so rows without tags stay compact.
function Tags({ children }: { children: React.ReactNode }) {
  if (Children.toArray(children).length === 0) return null;
  return <span className="mt-1 flex flex-wrap gap-1">{children}</span>;
}

// Host package pills, with running-image vulnerabilities as a separate
// muted figure: the two are fixed differently and never summed.
function VulnsCell({ machine: m }: { machine: Machine }) {
  if (!m.reported) {
    return <span className="text-muted-foreground text-sm">Waiting for first report</span>;
  }
  const hostVulns = m.vulns.critical + m.vulns.high + m.vulns.medium + m.vulns.low;
  if (hostVulns === 0 && m.images.vulns === 0) {
    return <span className="text-muted-foreground text-sm">No open vulnerabilities</span>;
  }
  return (
    <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
      <CountPills vulns={m.vulns} />
      {m.images.vulns > 0 && (
        <Tooltip>
          <TooltipTrigger asChild>
            <Link
              href={`/dashboard/hosts/${m.id}/images`}
              className="text-muted-foreground hover:text-foreground relative z-10 text-xs whitespace-nowrap tabular-nums hover:underline"
            >
              +{m.images.vulns} in images
            </Link>
          </TooltipTrigger>
          <TooltipContent>{imageVulnsTitle(m.images)}</TooltipContent>
        </Tooltip>
      )}
    </span>
  );
}
