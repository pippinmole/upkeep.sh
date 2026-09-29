import { Flame } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { formatEpss, isSeverity, SEVERITY_LABEL, type Severity } from "@/lib/severity";

// The one place severity colours live, on the --sev-* tokens in
// globals.css. Tinted background + strong -fg text in both themes (text
// contrast is checked against the tint, not the page).
const SEVERITY_CLASS: Record<Severity, string> = {
  critical: "border-sev-critical/40 bg-sev-critical/10 text-sev-critical-fg",
  high: "border-sev-high/40 bg-sev-high/10 text-sev-high-fg",
  medium: "border-sev-medium/40 bg-sev-medium/15 text-sev-medium-fg",
  unknown: "border-dashed border-sev-unknown/50 bg-sev-unknown/10 text-sev-unknown-fg",
  low: "border-sev-low/40 bg-sev-low/10 text-sev-low-fg",
  negligible: "border-border bg-muted text-muted-foreground",
};

// Solid severity colour for charts and bars.
export function severityColorVar(severity: string | null): string {
  const s: Severity = isSeverity(severity) ? severity : "unknown";
  return s === "negligible" ? "var(--muted-foreground)" : `var(--sev-${s})`;
}

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
        "bg-kev text-kev-fg hover:bg-kev gap-1 border-transparent font-semibold whitespace-nowrap shadow-none",
        className,
      )}
      title="Known exploited: listed in CISA's Known Exploited Vulnerabilities catalog"
    >
      <Flame aria-hidden />
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
        "border-accent-pro/40 bg-accent-pro/10 text-accent-pro-fg font-medium whitespace-nowrap",
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
