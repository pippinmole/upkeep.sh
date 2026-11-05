import { Flame } from "lucide-react";

import { lowOnlyCount, type MachineRow } from "@/lib/machines";
import { cn } from "@/lib/utils";

const PILLS = [
  { key: "critical", className: "bg-sev-critical-pill text-sev-critical-pill-fg" },
  { key: "high", className: "bg-sev-high-pill text-sev-high-pill-fg" },
  { key: "medium", className: "bg-sev-medium-pill text-sev-medium-pill-fg" },
] as const;

// Open host package vulnerabilities as critical / high / medium pills, in
// fixed slots so the columns line up down the list. Zero is a muted "0",
// not an empty pill. Container images are never counted in here.
export function CountPills({ vulns }: { vulns: MachineRow["vulns"] }) {
  const low = lowOnlyCount(vulns);
  return (
    <span className="inline-flex items-center gap-1 text-xs font-semibold tabular-nums">
      {PILLS.map(({ key, className }) => {
        const n = vulns[key];
        return (
          <span
            key={key}
            className={cn(
              "inline-flex h-5 min-w-7 items-center justify-center rounded-md px-1.5",
              n > 0 ? className : "text-muted-foreground font-normal",
            )}
          >
            <span className="sr-only">{`${n} ${key}`}</span>
            <span aria-hidden>{n}</span>
          </span>
        );
      })}
      {low !== null && (
        <span className="text-muted-foreground ml-1 font-normal whitespace-nowrap tabular-nums">
          {low} low
        </span>
      )}
      {vulns.kev > 0 && (
        <span
          title="Known exploited: listed in CISA's Known Exploited Vulnerabilities catalog"
          className="bg-kev text-kev-fg ml-1 inline-flex h-5 items-center gap-1 rounded-md px-1.5 whitespace-nowrap"
        >
          <Flame aria-hidden className="size-3" />
          {vulns.kev} KEV
        </span>
      )}
    </span>
  );
}
