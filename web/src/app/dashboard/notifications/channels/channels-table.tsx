"use client";

import { CheckCircle2, Loader2, MoreHorizontal, Plus, XCircle } from "lucide-react";
import { useState, useTransition } from "react";

import { DataTable } from "@/components/data-table/data-table";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { CHANNEL_TYPES, channelTarget, channelType } from "@/lib/notifiers";
import type { ChannelRow } from "@/lib/queries-notifications";
import { relativeTime } from "@/lib/time";

import {
  deleteChannel,
  sendTestNotification,
  setChannelEnabled,
  type TestResult,
} from "../actions";
import { ChannelDialog } from "../channel-dialog";
import { ConfirmDialog, DeliveryStatusBadge, EnabledBadge } from "../shared";

const TYPE_OPTIONS = CHANNEL_TYPES.map((t) => ({ value: t.type, label: t.label }));

function TestResultDialog({
  open,
  onOpenChange,
  pending,
  result,
  error,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  pending: boolean;
  result: TestResult | null;
  error: string | null;
}) {
  const ok = result?.status === "delivered";
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Test notification</DialogTitle>
          <DialogDescription>
            Sent by the worker through the same path as real alerts.
          </DialogDescription>
        </DialogHeader>
        {pending ? (
          <p className="flex items-center gap-2 text-sm">
            <Loader2 className="size-4 animate-spin" /> Sending…
          </p>
        ) : error ? (
          <p className="text-destructive text-sm">{error}</p>
        ) : result ? (
          <div className="flex flex-col gap-2 text-sm">
            <p className="flex items-center gap-2 font-medium">
              {ok ? (
                <CheckCircle2 className="size-4 text-emerald-600" />
              ) : (
                <XCircle className="text-destructive size-4" />
              )}
              {ok
                ? "Delivered"
                : result.status === "failed"
                  ? "Failed"
                  : "Still pending (is the worker running?)"}
              {result.statusCode !== null && (
                <span className="text-muted-foreground font-normal">HTTP {result.statusCode}</span>
              )}
            </p>
            {result.error && (
              <pre className="bg-muted overflow-x-auto rounded-md p-2 text-xs whitespace-pre-wrap">
                {result.error}
              </pre>
            )}
          </div>
        ) : null}
        <DialogFooter>
          <Button onClick={() => onOpenChange(false)}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ChannelActions({ channel }: { channel: ChannelRow }) {
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [testOpen, setTestOpen] = useState(false);
  const [test, setTest] = useState<{ result: TestResult | null; error: string | null }>({
    result: null,
    error: null,
  });
  const [testing, startTest] = useTransition();
  const [, startToggle] = useTransition();

  function runTest() {
    setTest({ result: null, error: null });
    setTestOpen(true);
    startTest(async () => {
      const res = await sendTestNotification(channel.id);
      setTest(res.ok ? { result: res, error: null } : { result: null, error: res.error });
    });
  }

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon" className="size-8" aria-label="Channel actions">
            <MoreHorizontal className="size-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem onSelect={runTest}>Send test</DropdownMenuItem>
          <DropdownMenuItem onSelect={() => setEditing(true)}>Edit</DropdownMenuItem>
          <DropdownMenuItem
            onSelect={() =>
              startToggle(async () => {
                await setChannelEnabled(channel.id, !channel.enabled);
              })
            }
          >
            {channel.enabled ? "Disable" : "Enable"}
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem className="text-destructive" onSelect={() => setDeleting(true)}>
            Delete
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      {editing && (
        <ChannelDialog
          key={channel.id}
          open={editing}
          onOpenChange={setEditing}
          channel={channel}
        />
      )}
      <ConfirmDialog
        open={deleting}
        onOpenChange={setDeleting}
        title={`Delete ${channel.name}?`}
        description={
          channel.ruleCount > 0
            ? `It is used by ${channel.ruleCount} ${channel.ruleCount === 1 ? "rule" : "rules"}, which will stop sending here. The delivery log is kept.`
            : "The delivery log is kept."
        }
        confirmLabel="Delete"
        onConfirm={async () => {
          await deleteChannel(channel.id);
        }}
      />
      <TestResultDialog
        open={testOpen}
        onOpenChange={setTestOpen}
        pending={testing}
        result={test.result}
        error={test.error}
      />
    </>
  );
}

const col = dataTableColumnHelper<ChannelRow>();

const columns = col.columns([
  col.accessor("name", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Name" />,
    enableHiding: false,
    cell: ({ row }) => <span className="font-medium">{row.original.name}</span>,
  }),
  col.accessor("type", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Type" />,
    filterFn: "arrHas",
    cell: ({ row }) => channelType(row.original.type)?.label ?? row.original.type,
  }),
  col.accessor((c) => channelTarget(c.type, c.config), {
    id: "target",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Destination" />,
    cell: ({ getValue }) => (
      <span className="block max-w-80 truncate font-mono text-xs" title={getValue()}>
        {getValue() || "—"}
      </span>
    ),
  }),
  col.accessor("enabled", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Status" />,
    cell: ({ row }) => <EnabledBadge enabled={row.original.enabled} />,
  }),
  col.accessor("ruleCount", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Rules" />,
    cell: ({ row }) => <span className="tabular-nums">{row.original.ruleCount}</span>,
  }),
  col.accessor((c) => (c.lastDeliveryAt ? Date.parse(c.lastDeliveryAt) : 0), {
    id: "lastDelivery",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Last delivery" />,
    cell: ({ row }) =>
      row.original.lastStatus ? (
        <span className="inline-flex items-center gap-2 whitespace-nowrap">
          <DeliveryStatusBadge status={row.original.lastStatus as TestResult["status"]} />
          <span className="text-muted-foreground">{relativeTime(row.original.lastDeliveryAt)}</span>
        </span>
      ) : (
        <span className="text-muted-foreground">Never</span>
      ),
  }),
  col.display({
    id: "actions",
    enableHiding: false,
    cell: ({ row }) => <ChannelActions channel={row.original} />,
  }),
]);

export function AddChannelButton() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button onClick={() => setOpen(true)}>
        <Plus />
        Add channel
      </Button>
      {open && <ChannelDialog open={open} onOpenChange={setOpen} />}
    </>
  );
}

export function ChannelsTable({ channels }: { channels: ChannelRow[] }) {
  return (
    <DataTable
      columns={columns}
      data={channels}
      getRowId={(c) => c.id}
      searchPlaceholder="Search channels"
      facets={
        TYPE_OPTIONS.length > 1 ? [{ columnId: "type", title: "Type", options: TYPE_OPTIONS }] : []
      }
      emptyMessage="No channels match."
    />
  );
}
