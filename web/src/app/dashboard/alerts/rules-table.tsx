"use client";

import { MoreHorizontal, Plus } from "lucide-react";
import Link from "next/link";
import { useState, useTransition } from "react";

import { NOTIFICATION_SETTINGS_URL } from "@/components/notifications/links";
import { DataTable } from "@/components/data-table/data-table";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { durationLabel, eventTypeLabel, isFindingEvent, SEVERITY_FLOORS } from "@/lib/notifiers";
import type { ChannelRow, RuleRow, ScopeHost } from "@/lib/queries-notifications";

import { deleteRule, setRuleEnabled } from "@/app/dashboard/notification-actions";
import { RuleDialog } from "./rule-dialog";
import { ConfirmDialog, EnabledBadge } from "@/components/notifications/shared";

type Ctx = { channels: ChannelRow[]; hosts: ScopeHost[] };

function RuleActions({ rule, ctx }: { rule: RuleRow; ctx: Ctx }) {
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [, startToggle] = useTransition();
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon" className="size-8" aria-label="Rule actions">
            <MoreHorizontal className="size-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem onSelect={() => setEditing(true)}>Edit</DropdownMenuItem>
          <DropdownMenuItem
            onSelect={() =>
              startToggle(async () => {
                await setRuleEnabled(rule.id, !rule.enabled);
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
        description="Pending digest items for this rule are dropped. The delivery log is kept."
        confirmLabel="Delete"
        onConfirm={async () => {
          await deleteRule(rule.id);
        }}
      />
    </>
  );
}

function filtersText(r: RuleRow, hosts: ScopeHost[]): string {
  const parts: string[] = [];
  if (r.eventTypes.some(isFindingEvent)) {
    if (r.minSeverityRank > 0) {
      parts.push(SEVERITY_FLOORS.find((s) => s.rank === r.minSeverityRank)?.label ?? "");
    }
    if (r.kevOnly) parts.push("KEV only");
  }
  if (r.hostIds) {
    const names = r.hostIds.map((id) => {
      const h = hosts.find((h) => h.id === id);
      if (!h) return "deleted host";
      return h.archived ? `${h.hostname} (archived)` : h.hostname;
    });
    parts.push(names.length <= 2 ? names.join(", ") : `${names.length} hosts`);
  } else {
    parts.push("All hosts");
  }
  return parts.join(" · ");
}

const col = dataTableColumnHelper<RuleRow>();

function makeColumns(ctx: Ctx) {
  return col.columns([
    col.accessor("name", {
      header: ({ column }) => <DataTableColumnHeader column={column} title="Rule" />,
      enableHiding: false,
      cell: ({ row }) => <span className="font-medium">{row.original.name}</span>,
    }),
    col.accessor((r) => r.eventTypes.join(","), {
      id: "events",
      header: "Events",
      enableSorting: false,
      cell: ({ row }) => (
        <span className="flex flex-wrap gap-1">
          {row.original.eventTypes.map((t) => (
            <Badge key={t} variant="outline" className="font-normal whitespace-nowrap">
              {eventTypeLabel(t)}
            </Badge>
          ))}
        </span>
      ),
    }),
    col.accessor((r) => filtersText(r, ctx.hosts), {
      id: "filters",
      header: "Filters",
      enableSorting: false,
      cell: ({ getValue }) => <span className="text-sm">{getValue()}</span>,
    }),
    col.accessor((r) => r.channels.map((c) => c.name).join(", "), {
      id: "channels",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Channels" />,
      // Channels are managed under Settings; link there rather than to nowhere.
      cell: ({ getValue }) =>
        getValue() ? (
          <Link href={NOTIFICATION_SETTINGS_URL} className="hover:underline">
            {getValue()}
          </Link>
        ) : (
          <span className="text-muted-foreground">None</span>
        ),
    }),
    col.accessor(
      (r) => (r.digest ? `Digest, every ${durationLabel(r.digestIntervalSeconds)}` : "Immediate"),
      {
        id: "delivery",
        header: ({ column }) => <DataTableColumnHeader column={column} title="Delivery" />,
        cell: ({ getValue, row }) => (
          <span className="whitespace-nowrap">
            {getValue()}
            <span className="text-muted-foreground block text-xs">
              dedup {durationLabel(row.original.dedupWindowSeconds).toLowerCase()}
            </span>
          </span>
        ),
      },
    ),
    col.accessor("enabled", {
      header: ({ column }) => <DataTableColumnHeader column={column} title="Status" />,
      cell: ({ row }) => <EnabledBadge enabled={row.original.enabled} />,
    }),
    col.display({
      id: "actions",
      enableHiding: false,
      cell: ({ row }) => <RuleActions rule={row.original} ctx={ctx} />,
    }),
  ]);
}

export function AddRuleButton(ctx: Ctx) {
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

export function RulesTable({ rules, ...ctx }: { rules: RuleRow[] } & Ctx) {
  return (
    <DataTable
      columns={makeColumns(ctx)}
      data={rules}
      getRowId={(r) => r.id}
      searchPlaceholder="Search rules"
      emptyMessage="No rules match."
    />
  );
}
