import {
  BellOff,
  BellRing,
  Bug,
  CalendarX,
  Clock,
  Container,
  Copy,
  Flame,
  type LucideIcon,
  Megaphone,
  PlugZap,
  RotateCw,
  ScanSearch,
  ShieldAlert,
  WifiOff,
} from "lucide-react";

import type { AttentionIcon as IconKey, AttentionTone } from "@/lib/attention/types";
import { cn } from "@/lib/utils";

const ICONS: Record<IconKey, LucideIcon> = {
  kev: Flame,
  vuln: Bug,
  socket: ShieldAlert,
  image: Container,
  alert: BellRing,
  stale: WifiOff,
  eol: CalendarX,
  reboot: RotateCw,
  collector: ScanSearch,
  delivery: BellOff,
  duplicate: Copy,
  agent: PlugZap,
  channel: Megaphone,
  waiting: Clock,
};

const TONE_CLASS: Record<AttentionTone, string> = {
  kev: "bg-kev/10 text-kev",
  danger: "bg-sev-critical/10 text-sev-critical-fg",
  warning: "bg-warning/10 text-warning-fg",
  info: "bg-info/10 text-info-fg",
  neutral: "bg-muted text-muted-foreground",
};

// The coloured icon chip in front of a "Needs attention" row.
export function AttentionIcon({ icon, tone }: { icon: IconKey; tone: AttentionTone }) {
  const Icon = ICONS[icon];
  return (
    <span
      className={cn(
        "flex size-8 shrink-0 items-center justify-center rounded-md",
        TONE_CLASS[tone],
      )}
    >
      <Icon className="size-4" aria-hidden />
    </span>
  );
}
