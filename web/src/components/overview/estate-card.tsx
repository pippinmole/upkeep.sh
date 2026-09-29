import Link from "next/link";

import { Card, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { EstateHealth, HostHealthState } from "@/lib/queries-overview";
import { cn } from "@/lib/utils";

import { plural } from "./cards";

// The Overview's "Estate" card: host health counts, one square per host
// coloured by its worst state (worst first), and the Docker footprint.

const MAX_SQUARES = 60;

const STATE: Record<HostHealthState, { label: string; square: string; rank: number }> = {
  kev: { label: "Known-exploited vulnerability", square: "bg-kev", rank: 0 },
  critical: { label: "Critical vulnerability", square: "bg-sev-critical", rank: 1 },
  reboot: { label: "Reboot required", square: "bg-warning", rank: 2 },
  stale: { label: "Not reporting", square: "bg-muted-foreground/60", rank: 3 },
  waiting: {
    label: "Waiting for first report",
    square: "border border-dashed border-muted-foreground bg-transparent",
    rank: 4,
  },
  ok: { label: "OK", square: "bg-success", rank: 5 },
};

const LEGEND: HostHealthState[] = ["kev", "critical", "reboot", "stale", "waiting", "ok"];

export function EstateCard({ estate, className }: { estate: EstateHealth; className?: string }) {
  const { hosts, signals } = estate;
  const counts = {
    ok: hosts.filter((h) => h.state === "ok").length,
    stale: hosts.filter((h) => h.stale && h.reported).length,
    reboot: hosts.filter((h) => h.reboot).length,
  };
  const sorted = [...hosts].sort((a, b) => STATE[a.state].rank - STATE[b.state].rank);
  const shown = sorted.slice(0, MAX_SQUARES);
  const more = hosts.length - shown.length;
  const present = new Set(hosts.map((h) => h.state));

  return (
    <Card className={cn("gap-4", className)}>
      <CardHeader>
        <CardTitle>Estate</CardTitle>
        <CardAction>
          <Link
            href="/dashboard/hosts"
            className="text-muted-foreground hover:text-foreground text-sm hover:underline"
          >
            All hosts
          </Link>
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div>
          <p className="text-3xl font-semibold tabular-nums">{hosts.length}</p>
          <p className="text-muted-foreground text-sm">
            {hosts.length === 1 ? "host" : "hosts"}:{" "}
            <span className="tabular-nums">{counts.ok}</span> ok ·{" "}
            <span className="tabular-nums">{counts.stale}</span> not reporting ·{" "}
            <span className="tabular-nums">{counts.reboot}</span> need a reboot
          </p>
        </div>

        {hosts.length > 0 && (
          <div className="flex flex-col gap-2">
            <ul className="flex flex-wrap gap-1" aria-label="Host health">
              {shown.map((h) => (
                <li key={h.id}>
                  <Link
                    href={`/dashboard/hosts/${h.id}`}
                    title={`${h.name}: ${STATE[h.state].label}`}
                    className={cn(
                      "focus-visible:ring-ring block size-4 rounded-sm transition-opacity hover:opacity-70 focus-visible:ring-2 focus-visible:ring-offset-1 focus-visible:outline-hidden",
                      STATE[h.state].square,
                    )}
                  >
                    <span className="sr-only">
                      {h.name}: {STATE[h.state].label}
                    </span>
                  </Link>
                </li>
              ))}
              {more > 0 && (
                <li>
                  <Link
                    href="/dashboard/hosts"
                    className="text-muted-foreground hover:text-foreground text-xs leading-4 tabular-nums hover:underline"
                  >
                    +{more}
                  </Link>
                </li>
              )}
            </ul>
            <ul className="text-muted-foreground flex flex-wrap gap-x-3 gap-y-1 text-xs">
              {LEGEND.filter((s) => present.has(s)).map((s) => (
                <li key={s} className="flex items-center gap-1.5">
                  <span aria-hidden className={cn("size-2.5 rounded-xs", STATE[s].square)} />
                  {STATE[s].label}
                </li>
              ))}
            </ul>
          </div>
        )}

        <p className="text-muted-foreground border-t pt-3 text-sm">
          <span className="text-foreground tabular-nums">
            {plural(signals.containers, "container", "containers")}
          </span>{" "}
          ·{" "}
          <Link href="/dashboard/images" className="text-foreground tabular-nums hover:underline">
            {plural(signals.images, "image", "images")}
          </Link>
        </p>
      </CardContent>
    </Card>
  );
}
