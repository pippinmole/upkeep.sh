"use client";

import { Bell, Loader2, type LucideIcon, Webhook } from "lucide-react";
import { type ReactNode, useTransition } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { channelType } from "@/lib/notifiers";
import type { ChannelRow, DeliveryRow } from "@/lib/queries-notifications";
import { cn } from "@/lib/utils";

export const DELIVERY_STATUS_OPTIONS: { value: DeliveryRow["status"]; label: string }[] = [
  { value: "delivered", label: "Delivered" },
  { value: "retrying", label: "Retrying" },
  { value: "pending", label: "Pending" },
  { value: "failed", label: "Failed" },
];

const STATUS_CLASS: Record<DeliveryRow["status"], string> = {
  delivered: "border-emerald-600/40 bg-emerald-500/10 text-emerald-800 dark:text-emerald-200",
  retrying: "border-amber-600/40 bg-amber-400/15 text-amber-900 dark:text-amber-200",
  pending: "border-dashed text-muted-foreground",
  failed: "border-red-600/40 bg-red-600/10 text-red-800 dark:text-red-200",
};

export function DeliveryStatusBadge({ status }: { status: DeliveryRow["status"] }) {
  return (
    <Badge variant="outline" className={cn("whitespace-nowrap", STATUS_CLASS[status])}>
      {DELIVERY_STATUS_OPTIONS.find((o) => o.value === status)?.label ?? status}
    </Badge>
  );
}

export function EnabledBadge({ enabled }: { enabled: boolean }) {
  return enabled ? (
    <Badge
      variant="outline"
      className="border-emerald-600/40 bg-emerald-500/10 whitespace-nowrap text-emerald-800 dark:text-emerald-200"
    >
      Enabled
    </Badge>
  ) : (
    <Badge variant="outline" className="bg-muted text-muted-foreground whitespace-nowrap">
      Disabled
    </Badge>
  );
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  onConfirm: () => Promise<void>;
}) {
  const [pending, startTransition] = useTransition();
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            disabled={pending}
            onClick={() =>
              startTransition(async () => {
                await onConfirm();
                onOpenChange(false);
              })
            }
          >
            {pending && <Loader2 className="animate-spin" />}
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function FieldError({ msg }: { msg?: string }) {
  return msg ? <p className="text-destructive text-xs">{msg}</p> : null;
}

export const toggle = (list: string[], v: string) =>
  list.includes(v) ? list.filter((x) => x !== v) : [...list, v];

// A scrollable list of checkboxes (rule events, hosts, channels).
export function CheckList<T>({
  items,
  selected,
  onToggle,
  id,
  label,
}: {
  items: T[];
  selected: string[];
  onToggle: (key: string) => void;
  id: (t: T) => string;
  label: (t: T) => ReactNode;
}) {
  return (
    <div className="max-h-40 overflow-y-auto rounded-md border p-2">
      {items.map((t) => (
        <label key={id(t)} className="flex items-center gap-2 py-1 text-sm">
          <input
            type="checkbox"
            className="accent-primary size-4"
            checked={selected.includes(id(t))}
            onChange={() => onToggle(id(t))}
          />
          {label(t)}
        </label>
      ))}
    </div>
  );
}

// Channel picker shared by alert rules and report schedules.
export function ChannelCheckList({
  channels,
  selected,
  onToggle,
}: {
  channels: Pick<ChannelRow, "id" | "name" | "type" | "enabled">[];
  selected: string[];
  onToggle: (id: string) => void;
}) {
  return (
    <CheckList
      items={channels}
      selected={selected}
      onToggle={onToggle}
      id={(c) => c.id}
      label={(c) => (
        <span>
          {c.name}{" "}
          <span className="text-muted-foreground">
            ({channelType(c.type)?.label ?? c.type}
            {!c.enabled && ", disabled"})
          </span>
        </span>
      )}
    />
  );
}

const CHANNEL_TYPE_ICONS: Record<string, LucideIcon> = {
  webhook: Webhook,
};

// Icon for a channel type; types without one fall back to a bell.
export function channelTypeIcon(type: string): LucideIcon {
  return CHANNEL_TYPE_ICONS[type] ?? Bell;
}
