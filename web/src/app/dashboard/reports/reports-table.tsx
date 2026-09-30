"use client";

import { CheckCircle2, Loader2, MoreHorizontal, Plus, Send } from "lucide-react";
import Link from "next/link";
import { useState, useTransition } from "react";

import { DataTable } from "@/components/data-table/data-table";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import { reportHref, scheduleReportsHref } from "@/components/notifications/links";
import { ConfirmDialog, EnabledBadge } from "@/components/notifications/shared";
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
import type { ChannelRow } from "@/lib/queries-notifications";
import type { ScheduleRow } from "@/lib/queries-reports";
import { cadenceSummary, formatRunAt, NEXT_RUN_PENDING } from "@/lib/report-schedules";
import { formatDateTime, relativeTime } from "@/lib/time";
import { adminOnly } from "@/components/viewer-context";

import {
  deleteReportSchedule,
  sendReportNow,
  setReportScheduleEnabled,
} from "@/app/dashboard/notification-actions";
import { ScheduleDialog } from "./schedule-dialog";

type SendState = { pending: boolean; error: string | null };

function SendNowDialog({
  open,
  onOpenChange,
  state,
  schedule,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  state: SendState;
  schedule: Pick<ScheduleRow, "id" | "channels">;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Send report now</DialogTitle>
          <DialogDescription>
            A real report: stored, sent to the schedule&apos;s channels, and compared with by the
            next one.
          </DialogDescription>
        </DialogHeader>
        {state.pending ? (
          <p className="flex items-center gap-2 text-sm">
            <Loader2 className="size-4 animate-spin" /> Queuing…
          </p>
        ) : state.error ? (
          <p className="text-destructive text-sm">{state.error}</p>
        ) : (
          <div className="flex flex-col gap-2 text-sm">
            <p className="flex items-center gap-2 font-medium">
              <CheckCircle2 className="text-success size-4" />
              Report queued; it&apos;ll appear under{" "}
              <Link
                href={scheduleReportsHref(schedule.id)}
                className="underline underline-offset-4"
              >
                past reports
              </Link>{" "}
              in a few seconds.
            </p>
            {schedule.channels.length === 0 && (
              <p className="text-muted-foreground">
                This schedule has no channels left, so the report is stored but not sent anywhere.
              </p>
            )}
          </div>
        )}
        <DialogFooter>
          <Button onClick={() => onOpenChange(false)}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// "Send now" state and its result dialog, for the table's menu and the
// past reports page's button.
export function useSendNow(schedule: Pick<ScheduleRow, "id" | "channels">) {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, startSend] = useTransition();
  function send() {
    setError(null);
    setOpen(true);
    startSend(async () => {
      const res = await sendReportNow(schedule.id);
      setError(res.ok ? null : res.error);
    });
  }
  const dialog = (
    <SendNowDialog
      open={open}
      onOpenChange={setOpen}
      state={{ pending, error }}
      schedule={schedule}
    />
  );
  return { send, dialog };
}

function SendNowButtonControl({ schedule }: { schedule: Pick<ScheduleRow, "id" | "channels"> }) {
  const { send, dialog } = useSendNow(schedule);
  return (
    <>
      <Button variant="outline" onClick={send}>
        <Send />
        Send now
      </Button>
      {dialog}
    </>
  );
}

type Ctx = { channels: ChannelRow[] };

function ScheduleActionsControl({ schedule, ctx }: { schedule: ScheduleRow; ctx: Ctx }) {
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [, startToggle] = useTransition();
  const { send, dialog } = useSendNow(schedule);
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon" className="size-8" aria-label="Schedule actions">
            <MoreHorizontal className="size-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem onSelect={send}>Send now</DropdownMenuItem>
          <DropdownMenuItem asChild>
            <Link href={scheduleReportsHref(schedule.id)}>Past reports</Link>
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => setEditing(true)}>Edit</DropdownMenuItem>
          <DropdownMenuItem
            onSelect={() =>
              startToggle(async () => {
                await setReportScheduleEnabled(schedule.id, !schedule.enabled);
              })
            }
          >
            {schedule.enabled ? "Disable" : "Enable"}
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem className="text-destructive" onSelect={() => setDeleting(true)}>
            Delete
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      {editing && (
        <ScheduleDialog
          key={schedule.id}
          open={editing}
          onOpenChange={setEditing}
          schedule={schedule}
          channels={ctx.channels}
        />
      )}
      <ConfirmDialog
        open={deleting}
        onOpenChange={setDeleting}
        title={`Delete ${schedule.name}?`}
        description={
          schedule.reportCount > 0
            ? `Its ${schedule.reportCount} past ${schedule.reportCount === 1 ? "report is" : "reports are"} deleted too, and links to them in emails and notifications stop working. The delivery log is kept.`
            : "The delivery log is kept."
        }
        confirmLabel="Delete"
        onConfirm={async () => {
          await deleteReportSchedule(schedule.id);
        }}
      />
      {dialog}
    </>
  );
}

const col = dataTableColumnHelper<ScheduleRow>();

function makeColumns(ctx: Ctx) {
  return col.columns([
    col.accessor("name", {
      header: ({ column }) => <DataTableColumnHeader column={column} title="Name" />,
      enableHiding: false,
      cell: ({ row }) => <span className="font-medium">{row.original.name}</span>,
    }),
    col.accessor((s) => cadenceSummary(s), {
      id: "cadence",
      header: "Schedule",
      enableSorting: false,
      cell: ({ getValue }) => <span className="text-sm">{getValue()}</span>,
    }),
    col.accessor((s) => s.channels.map((c) => c.name).join(", "), {
      id: "channels",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Channels" />,
      cell: ({ getValue }) => getValue() || <span className="text-muted-foreground">None</span>,
    }),
    col.accessor("enabled", {
      header: ({ column }) => <DataTableColumnHeader column={column} title="Status" />,
      cell: ({ row }) => <EnabledBadge enabled={row.original.enabled} />,
    }),
    col.accessor((s) => (s.nextRunAt ? Date.parse(s.nextRunAt) : 0), {
      id: "nextRun",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Next run" />,
      cell: ({ row }) => {
        const s = row.original;
        if (!s.enabled) return <span className="text-muted-foreground">—</span>;
        return (
          <span
            className={s.nextRunAt ? "whitespace-nowrap" : "text-muted-foreground"}
            title={
              s.nextRunAt ? formatDateTime(s.nextRunAt) : "The worker works it out within a minute"
            }
          >
            {formatRunAt(s.nextRunAt, s.timezone, NEXT_RUN_PENDING)}
          </span>
        );
      },
    }),
    col.accessor((s) => (s.lastRunAt ? Date.parse(s.lastRunAt) : 0), {
      id: "lastRun",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Last run" />,
      cell: ({ row }) => {
        const s = row.original;
        if (!s.lastRunAt) return <span className="text-muted-foreground">Never</span>;
        const when = relativeTime(s.lastRunAt);
        return s.latestReportId ? (
          <Link
            href={reportHref(s.latestReportId)}
            className="whitespace-nowrap underline-offset-4 hover:underline"
            title={formatRunAt(s.lastRunAt, s.timezone)}
          >
            {when}
          </Link>
        ) : (
          <span className="whitespace-nowrap">{when}</span>
        );
      },
    }),
    col.display({
      id: "actions",
      enableHiding: false,
      cell: ({ row }) => <ScheduleActions schedule={row.original} ctx={ctx} />,
    }),
  ]);
}

// A schedule needs somewhere to send to: disabled, with the reason on
// hover, until a channel exists (same as AddRuleButton).
function AddScheduleButtonControl(ctx: Ctx) {
  const [open, setOpen] = useState(false);
  const noChannels = ctx.channels.length === 0;
  return (
    <>
      <span title={noChannels ? "Add a channel first" : undefined} className="inline-flex">
        <Button onClick={() => setOpen(true)} disabled={noChannels}>
          <Plus />
          New schedule
        </Button>
      </span>
      {open && <ScheduleDialog open={open} onOpenChange={setOpen} {...ctx} />}
    </>
  );
}

export function ReportsTable({ schedules, ...ctx }: { schedules: ScheduleRow[] } & Ctx) {
  return (
    <DataTable
      columns={makeColumns(ctx)}
      data={schedules}
      getRowId={(s) => s.id}
      searchPlaceholder="Search schedules"
      emptyMessage="No schedules match."
    />
  );
}

// Write controls: admins only (docs/MEMBERS.md); the server re-checks.
export const SendNowButton = adminOnly(SendNowButtonControl);
const ScheduleActions = adminOnly(ScheduleActionsControl);
export const AddScheduleButton = adminOnly(AddScheduleButtonControl);
