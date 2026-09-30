"use client";

import { MoreHorizontal, Plus } from "lucide-react";
import { useState, useTransition } from "react";

import { ConfirmDialog } from "@/components/notifications/shared";
import { adminOnly } from "@/components/viewer-context";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { AlertRuleRow } from "@/lib/queries-alerts";
import type { ChannelRow, ScopeHost } from "@/lib/queries-notifications";

import { deleteAlertRule, setAlertRuleEnabled } from "@/app/dashboard/alert-rule-actions";

import { RuleDialog } from "./rule-dialog";

export type RuleCtx = { channels: ChannelRow[]; hosts: ScopeHost[] };

function RuleActionsControl({ rule, ctx }: { rule: AlertRuleRow; ctx: RuleCtx }) {
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [, startToggle] = useTransition();
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            className="size-8"
            aria-label={`Actions for ${rule.name}`}
          >
            <MoreHorizontal className="size-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem onSelect={() => setEditing(true)}>Edit</DropdownMenuItem>
          <DropdownMenuItem
            onSelect={() =>
              startToggle(async () => {
                await setAlertRuleEnabled(rule.id, !rule.enabled);
              })
            }
          >
            {rule.enabled ? "Disable" : "Enable"}
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem className="text-destructive" onSelect={() => setDeleting(true)}>
            Delete
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      {editing && (
        <RuleDialog
          key={rule.id}
          open={editing}
          onOpenChange={setEditing}
          rule={rule}
          channels={ctx.channels}
          hosts={ctx.hosts}
        />
      )}
      <ConfirmDialog
        open={deleting}
        onOpenChange={setDeleting}
        title={`Delete ${rule.name}?`}
        description="Its firing alerts resolve without notifying, and its alert history and the delivery log are kept. Pending digest items are dropped."
        confirmLabel="Delete"
        onConfirm={async () => {
          await deleteAlertRule(rule.id);
        }}
      />
    </>
  );
}

function AddRuleButtonControl(ctx: RuleCtx) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button onClick={() => setOpen(true)}>
        <Plus />
        New rule
      </Button>
      {open && <RuleDialog open={open} onOpenChange={setOpen} {...ctx} />}
    </>
  );
}

// Write controls: admins only (docs/MEMBERS.md); the server re-checks.
export const RuleActions = adminOnly(RuleActionsControl);
export const AddRuleButton = adminOnly(AddRuleButtonControl);
