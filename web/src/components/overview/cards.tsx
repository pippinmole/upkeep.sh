import Link from "next/link";

import { SeverityBadge, severityColorVar } from "@/components/vuln/badges";
import { SEVERITIES, type Severity, type SeverityCounts } from "@/lib/severity";

// Small shared pieces: pluralizing and the severity bars on the host page.

export const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

// Open findings per severity bucket as bars of the total. `href` links each
// bucket to a filtered list when there is one.
export function SeverityBars({
  counts,
  total,
  href,
}: {
  counts: SeverityCounts;
  total: number;
  href?: (s: Severity) => string;
}) {
  return (
    <ul className="mt-3 flex flex-col gap-2">
      {SEVERITIES.map((s) => (
        <li key={s} className="flex items-center gap-3">
          {href ? (
            <Link href={href(s)} className="w-24 shrink-0">
              <SeverityBadge severity={s} />
            </Link>
          ) : (
            <span className="w-24 shrink-0">
              <SeverityBadge severity={s} />
            </span>
          )}
          <div className="bg-muted h-2 flex-1 overflow-hidden rounded-full">
            <div
              className="h-full rounded-full"
              style={{
                width: `${total > 0 ? (counts[s] / total) * 100 : 0}%`,
                backgroundColor: severityColorVar(s),
              }}
            />
          </div>
          <span className="w-12 text-right text-sm tabular-nums">{counts[s]}</span>
        </li>
      ))}
    </ul>
  );
}
