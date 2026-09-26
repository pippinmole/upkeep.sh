import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { formatEpss, isSeverity, SEVERITY_LABEL, type Severity } from "@/lib/severity";

// The one place severity colours live. Tinted background + strong text in
// both themes (text contrast is checked against the tint, not the page), so
// badges stay readable in light and dark mode.
const SEVERITY_CLASS: Record<Severity, string> = {
  critical:
    "border-red-600/40 bg-red-600/10 text-red-800 dark:border-red-400/40 dark:bg-red-400/15 dark:text-red-200",
  high: "border-orange-600/40 bg-orange-500/10 text-orange-800 dark:border-orange-400/40 dark:bg-orange-400/15 dark:text-orange-200",
  medium:
    "border-amber-600/40 bg-amber-400/15 text-amber-900 dark:border-amber-400/40 dark:bg-amber-400/15 dark:text-amber-200",
  unknown:
    "border-dashed border-slate-500/50 bg-slate-500/10 text-slate-700 dark:border-slate-400/50 dark:text-slate-200",
  low: "border-sky-600/40 bg-sky-500/10 text-sky-800 dark:border-sky-400/40 dark:bg-sky-400/15 dark:text-sky-200",
  negligible: "border-border bg-muted text-muted-foreground",
};

export function SeverityBadge({
  severity,
  className,
  count,
}: {
  severity: string | null;
  className?: string;
  // Optional count shown after the label ("High 3").
  count?: number;
}) {
  const s: Severity = isSeverity(severity) ? severity : "unknown";
  return (
    <Badge
      variant="outline"
      className={cn("gap-1 font-medium whitespace-nowrap", SEVERITY_CLASS[s], className)}
    >
      {SEVERITY_LABEL[s]}
      {count !== undefined && <span className="tabular-nums">{count}</span>}
    </Badge>
  );
}

export function KevBadge({ className, count }: { className?: string; count?: number }) {
  return (
    <Badge
      className={cn(
        "gap-1 border-transparent bg-red-700 font-semibold whitespace-nowrap text-white shadow-none hover:bg-red-700 dark:bg-red-600",
        className,
      )}
      title="Known exploited: listed in CISA's Known Exploited Vulnerabilities catalog"
    >
      KEV
      {count !== undefined && <span className="tabular-nums">{count}</span>}
    </Badge>
  );
}

export function ProFixBadge({ className }: { className?: string }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "border-violet-600/40 bg-violet-500/10 font-medium whitespace-nowrap text-violet-800 dark:border-violet-400/40 dark:text-violet-200",
        className,
      )}
      title="The only fixed package is in Ubuntu Pro (ESM); the standard archive has no fix"
    >
      Fix requires Ubuntu Pro
    </Badge>
  );
}

export function NoFixBadge({ className }: { className?: string }) {
  return (
    <Badge
      variant="outline"
      className={cn("text-muted-foreground font-normal whitespace-nowrap", className)}
      title="No fixed version has been published for this release yet"
    >
      No fix yet
    </Badge>
  );
}

// Secondary signals in one muted line: EPSS, CVSS, distro priority.
export function ScoreLine({
  epss,
  cvss,
  distroSeverity,
}: {
  epss: number | null;
  cvss: number | null;
  distroSeverity: string | null;
}) {
  const parts = [
    epss !== null && `EPSS ${formatEpss(epss)}`,
    cvss !== null && `CVSS ${cvss.toFixed(1)}`,
    distroSeverity && `distro: ${distroSeverity}`,
  ].filter(Boolean);
  if (parts.length === 0) return null;
  return (
    <span className="text-muted-foreground text-xs whitespace-nowrap">{parts.join(" · ")}</span>
  );
}

// Fix column: fixed version (mono), Pro badge, or "No fix yet".
export function FixCell({
  fixedVersion,
  fixChannel,
}: {
  fixedVersion: string | null;
  fixChannel: string | null;
}) {
  if (!fixedVersion) return <NoFixBadge />;
  return (
    <div className="flex flex-col items-start gap-1">
      <span className="font-mono text-xs">{fixedVersion}</span>
      {fixChannel === "ubuntu-pro" && <ProFixBadge />}
    </div>
  );
}
