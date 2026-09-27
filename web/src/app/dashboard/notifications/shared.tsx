"use client";

import { Loader2 } from "lucide-react";
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
import type { DeliveryRow } from "@/lib/queries-notifications";
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
