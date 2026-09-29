import Link from "next/link";

import { SeverityBadge, severityColorVar } from "@/components/vuln/badges";
import { SEVERITIES, type Severity, type SeverityCounts } from "@/lib/severity";
import { cn } from "@/lib/utils";

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

export type MetricTone = "kev" | "critical" | "warning" | "neutral";

// Icon chip and value colour per tone; the value is only coloured when it
// is non-zero, so an all-clear row reads calm.
const METRIC_TONE: Record<MetricTone, { chip: string; value: string }> = {
  kev: { chip: "bg-kev/10 text-kev", value: "text-kev" },
  critical: { chip: "bg-sev-critical/10 text-sev-critical-fg", value: "text-sev-critical-fg" },
  warning: { chip: "bg-warning/10 text-warning-fg", value: "text-warning-fg" },
  neutral: { chip: "bg-muted text-muted-foreground", value: "" },
};

// The Overview's coloured stat row: one number, an icon in its tone, and a
// muted line under it. Links to the filtered list when `href` is set.
export function MetricCard({
  title,
  value,
  tone,
  icon,
  href,
  children,
}: {
  title: string;
  value: number;
  tone: MetricTone;
  icon: React.ReactNode;
  href?: string;
  children?: React.ReactNode;
}) {
  const t = METRIC_TONE[tone];
  const body = (
    <>
      <div className="flex items-center justify-between gap-2">
        <p className="text-muted-foreground text-sm font-medium">{title}</p>
        <span
          aria-hidden
          className={cn(
            "flex size-8 items-center justify-center rounded-md [&>svg]:size-4",
            t.chip,
          )}
        >
          {icon}
        </span>
      </div>
      <p className={cn("mt-1 text-3xl font-semibold tabular-nums", value > 0 && t.value)}>
        {value.toLocaleString("en-US")}
      </p>
      {children && <div className="text-muted-foreground mt-1 text-sm">{children}</div>}
    </>
  );
  const cls = "bg-card rounded-lg border p-4 shadow-xs";
  return href ? (
    <Link href={href} className={cn(cls, "hover:bg-accent/50 transition-colors")}>
      {body}
    </Link>
  ) : (
    <div className={cls}>{body}</div>
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
