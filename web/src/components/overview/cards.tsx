import Link from "next/link";

import { SeverityBadge } from "@/components/vuln/badges";
import { SEVERITIES, type Severity, type SeverityCounts } from "@/lib/severity";

// Building blocks of the Overview page (/dashboard), shared by its host
// package and container image sections.

export const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

export function StatCard({
  title,
  value,
  href,
  children,
}: {
  title: string;
  value: React.ReactNode;
  href?: string;
  children?: React.ReactNode;
}) {
  const body = (
    <>
      <p className="text-muted-foreground text-sm font-medium">{title}</p>
      <p className="mt-1 text-3xl font-semibold tabular-nums">{value}</p>
      {children && <div className="text-muted-foreground mt-2 text-sm">{children}</div>}
    </>
  );
  return href ? (
    <Link
      href={href}
      className="bg-card hover:bg-accent/50 rounded-lg border p-4 transition-colors"
    >
      {body}
    </Link>
  ) : (
    <div className="bg-card rounded-lg border p-4">{body}</div>
  );
}

// Card heading with a small label naming what the numbers count ("Host
// packages" / "Container images"), so the two sections never read as one
// total.
export function CardTitle({ scope, children }: { scope: string; children: React.ReactNode }) {
  return (
    <h2 className="font-semibold">
      <span className="text-muted-foreground block text-xs font-medium tracking-wide uppercase">
        {scope}
      </span>
      {children}
    </h2>
  );
}

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
              className="bg-foreground/60 h-full rounded-full"
              style={{ width: `${total > 0 ? (counts[s] / total) * 100 : 0}%` }}
            />
          </div>
          <span className="w-12 text-right text-sm tabular-nums">{counts[s]}</span>
        </li>
      ))}
    </ul>
  );
}
