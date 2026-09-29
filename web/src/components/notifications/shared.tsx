"use client";

import { Loader2 } from "lucide-react";
import { type ComponentType, type ReactNode, useTransition } from "react";

import { ChannelIcon } from "@/components/brand/channel-icon";
import { DELIVERY_STATUS_LABEL, deliveryStatusTone, StatusBadge } from "@/components/status";
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

const DELIVERY_STATUSES: DeliveryRow["status"][] = ["delivered", "retrying", "pending", "failed"];

export const DELIVERY_STATUS_OPTIONS: { value: DeliveryRow["status"]; label: string }[] =
  DELIVERY_STATUSES.map((value) => ({ value, label: DELIVERY_STATUS_LABEL[value] }));

export function DeliveryStatusBadge({ status }: { status: DeliveryRow["status"] }) {
  return (
    <StatusBadge
      tone={deliveryStatusTone(status) ?? "neutral"}
      label={DELIVERY_STATUS_LABEL[status] ?? status}
    />
  );
}

export function EnabledBadge({ enabled }: { enabled: boolean }) {
  return (
    <StatusBadge tone={enabled ? "success" : "neutral"} label={enabled ? "Enabled" : "Disabled"} />
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
        <span className="inline-flex items-center gap-1.5">
          <ChannelIcon type={c.type} className="text-muted-foreground size-4 shrink-0" />
          {c.name}
          <span className="text-muted-foreground">
            ({channelType(c.type)?.label ?? c.type}
            {!c.enabled && ", disabled"})
          </span>
        </span>
      )}
    />
  );
}

type ChannelTypeIconProps = { className?: string; "aria-hidden"?: boolean | "true" | "false" };

// One stable component per type, so callers can render the result as a
// component (`const Icon = channelTypeIcon(t); <Icon />`) without
// remounting it every render.
const CHANNEL_TYPE_ICONS = new Map<string, ComponentType<ChannelTypeIconProps>>();

// Icon for a channel type (see ChannelIcon); unknown types get a bell.
export function channelTypeIcon(type: string): ComponentType<ChannelTypeIconProps> {
  let Icon = CHANNEL_TYPE_ICONS.get(type);
  if (!Icon) {
    // The icon is always next to the channel's name or type label.
    const TypeIcon = ({ className }: ChannelTypeIconProps) => (
      <ChannelIcon type={type} className={className} />
    );
    TypeIcon.displayName = `ChannelTypeIcon(${type})`;
    CHANNEL_TYPE_ICONS.set(type, TypeIcon);
    Icon = TypeIcon;
  }
  return Icon;
}
