import type { ReactNode } from "react";

import { Badge } from "@/components/ui/badge";
import type { AgentStatus } from "@/lib/queries";
import type { DeliveryRow } from "@/lib/queries-notifications";
import { cn } from "@/lib/utils";

// Shared status vocabulary: pages map their domain states to a Tone here and
// never write colour classes themselves. Every indicator carries text, so
// state is never conveyed by colour alone.

export type Tone = "success" | "warning" | "danger" | "info" | "neutral" | "pending";

const DOT_CLASS: Record<Tone, string> = {
  success: "bg-success",
  warning: "bg-warning",
  danger: "bg-danger",
  info: "bg-info",
  neutral: "bg-muted-foreground/60",
  pending: "border border-dashed border-muted-foreground bg-transparent",
};

const BADGE_VARIANT = {
  success: "success",
  warning: "warning",
  danger: "danger",
  info: "info",
  neutral: "neutral",
  pending: "dashed",
} as const satisfies Record<Tone, string>;

function Dot({ tone, pulse }: { tone: Tone; pulse?: boolean }) {
  return (
    <span aria-hidden className="relative inline-flex size-2 shrink-0">
      {pulse && (
        <span
          className={cn(
            "absolute inline-flex size-full animate-ping rounded-full opacity-60 motion-reduce:hidden",
            DOT_CLASS[tone],
          )}
        />
      )}
      <span className={cn("relative inline-flex size-2 rounded-full", DOT_CLASS[tone])} />
    </span>
  );
}

export function StatusDot({
  tone,
  label,
  pulse,
  className,
}: {
  tone: Tone;
  label: string;
  pulse?: boolean;
  className?: string;
}) {
  return (
    <span className={cn("inline-flex items-center", className)} title={label}>
      <Dot tone={tone} pulse={pulse} />
      <span className="sr-only">{label}</span>
    </span>
  );
}

export function StatusBadge({
  tone,
  label,
  icon,
  title,
  className,
}: {
  tone: Tone;
  label: ReactNode;
  // Replaces the leading dot (e.g. a lucide icon or a ChannelIcon).
  icon?: ReactNode;
  title?: string;
  className?: string;
}) {
  return (
    <Badge
      variant={BADGE_VARIANT[tone]}
      className={cn("gap-1.5 whitespace-nowrap", className)}
      title={title}
    >
      {icon ?? <Dot tone={tone} />}
      {label}
    </Badge>
  );
}

// Agents: lib/queries.ts AgentStatus.
export const AGENT_STATUS_LABEL: Record<AgentStatus, string> = {
  online: "Online",
  stale: "Stale",
  never: "Never connected",
  revoked: "Revoked",
};

export function agentStatusTone(status: AgentStatus): Tone {
  switch (status) {
    case "online":
      return "success";
    case "stale":
      return "warning";
    case "never":
      return "pending";
    case "revoked":
      return "neutral";
  }
}

// Docker container / Swarm task state (`docker ps` vocabulary). Running is
// the normal case; restarting or dead means something that should run isn't.
export function containerStateTone(state: string | null): Tone {
  switch (state) {
    case "running":
      return "success";
    case "restarting":
    case "dead":
      return "warning";
    case "paused":
      return "info";
    default:
      return "neutral";
  }
}

// Notification deliveries: lib/queries-notifications.ts DeliveryRow.status.
export type DeliveryStatus = DeliveryRow["status"];

export const DELIVERY_STATUS_LABEL: Record<DeliveryStatus, string> = {
  delivered: "Delivered",
  retrying: "Retrying",
  pending: "Pending",
  failed: "Failed",
};

export function deliveryStatusTone(status: DeliveryStatus): Tone {
  switch (status) {
    case "delivered":
      return "success";
    case "retrying":
      return "warning";
    case "pending":
      return "pending";
    case "failed":
      return "danger";
  }
}
