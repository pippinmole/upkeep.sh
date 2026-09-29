import {
  BellOff,
  CheckCircle2,
  ChevronRight,
  Clock,
  Container,
  Flame,
  type LucideIcon,
  PlugZap,
  RotateCw,
  WifiOff,
} from "lucide-react";
import Link from "next/link";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { EstateHealth, HostHealth } from "@/lib/queries-overview";
import { cn } from "@/lib/utils";

import { plural } from "./cards";

// The Overview's ranked "what to do now" list: one row per kind of problem,
// most urgent first, each linking to where it is fixed. Collapses to an
// "All clear" row when there is nothing.

type Tone = "kev" | "danger" | "warning" | "info" | "neutral";

const TONE_CLASS: Record<Tone, string> = {
  kev: "bg-kev/10 text-kev",
  danger: "bg-sev-critical/10 text-sev-critical-fg",
  warning: "bg-warning/10 text-warning-fg",
  info: "bg-info/10 text-info-fg",
  neutral: "bg-muted text-muted-foreground",
};

type Item = {
  key: string;
  tone: Tone;
  icon: LucideIcon;
  title: string;
  detail?: string;
  count: number;
  href: string;
};

const MAX_NAMES = 3;

function names(xs: string[]): string {
  const shown = xs.slice(0, MAX_NAMES).join(", ");
  return xs.length > MAX_NAMES ? `${shown} and ${xs.length - MAX_NAMES} more` : shown;
}

// One host → its page; several → the list where they are.
function hostsHref(hosts: HostHealth[], many: string): string {
  return hosts.length === 1 ? `/dashboard/hosts/${hosts[0].id}` : many;
}

export function attentionItems(
  estate: EstateHealth,
  kev: { findings: number; hosts: number },
): Item[] {
  const { hosts, signals } = estate;
  const items: Item[] = [];
  if (kev.findings > 0) {
    items.push({
      key: "kev",
      tone: "kev",
      icon: Flame,
      title: `Known-exploited vulnerabilities on ${plural(kev.hosts, "host", "hosts")}`,
      detail: "Listed in CISA's KEV catalog: patch these first",
      count: kev.findings,
      href: "/dashboard/vulnerabilities?kev=1",
    });
  }
  if (signals.criticalImages > 0) {
    items.push({
      key: "images",
      tone: "danger",
      icon: Container,
      title: "Images in use with critical vulnerabilities",
      detail: "Rebuild or re-pull these images",
      count: signals.criticalImages,
      href: "/dashboard/images",
    });
  }
  const stale = hosts.filter((h) => h.stale && h.reported);
  if (stale.length > 0) {
    items.push({
      key: "stale",
      tone: "warning",
      icon: WifiOff,
      title: stale.length === 1 ? "Host not reporting" : "Hosts not reporting",
      detail: names(stale.map((h) => h.name)),
      count: stale.length,
      href: hostsHref(stale, "/dashboard/agents"),
    });
  }
  const reboot = hosts.filter((h) => h.reboot);
  if (reboot.length > 0) {
    items.push({
      key: "reboot",
      tone: "warning",
      icon: RotateCw,
      title: "Reboot required",
      detail: names(reboot.map((h) => h.name)),
      count: reboot.length,
      href: hostsHref(reboot, "/dashboard/hosts"),
    });
  }
  if (signals.failedDeliveries > 0) {
    items.push({
      key: "deliveries",
      tone: "warning",
      icon: BellOff,
      title: "Failed notification deliveries in the last 7 days",
      detail: "Check the channel's settings in the delivery log",
      count: signals.failedDeliveries,
      href: "/dashboard/alerts/log",
    });
  }
  if (signals.neverConnected.length > 0) {
    items.push({
      key: "never",
      tone: "info",
      icon: PlugZap,
      title:
        signals.neverConnected.length === 1 ? "Agent never connected" : "Agents never connected",
      detail: names(signals.neverConnected),
      count: signals.neverConnected.length,
      href: "/dashboard/agents",
    });
  }
  const waiting = hosts.filter((h) => !h.reported);
  if (waiting.length > 0) {
    items.push({
      key: "waiting",
      tone: "neutral",
      icon: Clock,
      title: "Waiting for a first report",
      detail: names(waiting.map((h) => h.name)),
      count: waiting.length,
      href: hostsHref(waiting, "/dashboard/hosts"),
    });
  }
  return items;
}

export function NeedsAttention({ items, className }: { items: Item[]; className?: string }) {
  return (
    <Card className={cn("gap-3", className)}>
      <CardHeader>
        <CardTitle>Needs attention</CardTitle>
        <CardDescription>Most urgent first.</CardDescription>
      </CardHeader>
      <CardContent className="px-3">
        {items.length === 0 ? (
          <div className="flex items-center gap-3 rounded-md px-3 py-2.5">
            <span className="bg-success/10 text-success-fg flex size-8 shrink-0 items-center justify-center rounded-md">
              <CheckCircle2 className="size-4" aria-hidden />
            </span>
            <div>
              <p className="text-sm font-medium">All clear</p>
              <p className="text-muted-foreground text-sm">
                No known-exploited vulnerabilities, silent hosts or pending reboots.
              </p>
            </div>
          </div>
        ) : (
          <ul className="flex flex-col">
            {items.map((it) => (
              <li key={it.key}>
                <Link
                  href={it.href}
                  className="hover:bg-accent/50 focus-visible:ring-ring flex items-center gap-3 rounded-md px-3 py-2.5 transition-colors focus-visible:ring-2 focus-visible:outline-hidden"
                >
                  <span
                    className={cn(
                      "flex size-8 shrink-0 items-center justify-center rounded-md",
                      TONE_CLASS[it.tone],
                    )}
                  >
                    <it.icon className="size-4" aria-hidden />
                  </span>
                  <span className="flex min-w-0 flex-1 flex-col">
                    <span className="text-sm font-medium">{it.title}</span>
                    {it.detail && (
                      <span className="text-muted-foreground truncate text-sm" title={it.detail}>
                        {it.detail}
                      </span>
                    )}
                  </span>
                  <span className="text-lg font-semibold tabular-nums">
                    {it.count.toLocaleString("en-US")}
                  </span>
                  <ChevronRight className="text-muted-foreground size-4 shrink-0" aria-hidden />
                </Link>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
