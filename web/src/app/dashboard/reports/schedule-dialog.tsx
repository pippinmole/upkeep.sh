"use client";

import { AlertTriangle, Loader2 } from "lucide-react";
import { useState, useTransition } from "react";

import { NotificationSettingsLink } from "@/components/notifications/links";
import { ChannelCheckList, FieldError, toggle } from "@/components/notifications/shared";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { ChannelRow } from "@/lib/queries-notifications";
import type { ScheduleRow } from "@/lib/queries-reports";
import {
  browserTimeZone,
  hourLabel,
  MAX_DAY_OF_MONTH,
  type ScheduleInput,
  timeZoneOptions,
  WEEKDAYS,
} from "@/lib/report-schedules";

import { createReportSchedule, updateReportSchedule } from "@/app/dashboard/notification-actions";

const HOURS = Array.from({ length: 24 }, (_, h) => h);
const DAYS = Array.from({ length: MAX_DAY_OF_MONTH }, (_, i) => i + 1);

// Create (schedule = undefined) or edit a report schedule. Rendered only
// while open, so the browser's timezone default is read on the client.
export function ScheduleDialog({
  open,
  onOpenChange,
  schedule,
  channels,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  schedule?: ScheduleRow;
  channels: ChannelRow[];
}) {
  const [v, setV] = useState<ScheduleInput>(() => ({
    name: schedule?.name ?? "",
    enabled: schedule?.enabled ?? true,
    cadence: schedule?.cadence ?? "weekly",
    weekday: schedule?.weekday ?? 1,
    dayOfMonth: schedule?.dayOfMonth ?? 1,
    hour: schedule?.hour ?? 9,
    timezone: schedule?.timezone ?? browserTimeZone(),
    channelIds:
      schedule?.channels.map((c) => c.id) ?? (channels.length === 1 ? [channels[0].id] : []),
  }));
  const [zones] = useState(() => timeZoneOptions(v.timezone));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const set = <K extends keyof ScheduleInput>(k: K, val: ScheduleInput[K]) =>
    setV((prev) => ({ ...prev, [k]: val }));

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    startTransition(async () => {
      const res = schedule
        ? await updateReportSchedule(schedule.id, v)
        : await createReportSchedule(v);
      if (!res.ok) {
        setError(res.error);
        setErrors(res.fieldErrors ?? {});
        return;
      }
      onOpenChange(false);
    });
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{schedule ? `Edit ${schedule.name}` : "New report schedule"}</DialogTitle>
          <DialogDescription>
            A report of your whole estate (what to patch, what changed, what isn&apos;t reporting),
            sent to the channels you pick.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="flex flex-col gap-4">
          {error && (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="schedule-name">Name</Label>
            <Input
              id="schedule-name"
              value={v.name}
              maxLength={100}
              placeholder="e.g. Monday patch list"
              aria-invalid={!!errors.name}
              onChange={(e) => set("name", e.target.value)}
            />
            <FieldError msg={errors.name} />
          </div>

          <div className="grid gap-3 sm:grid-cols-3">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="schedule-cadence">Every</Label>
              <Select
                value={v.cadence}
                onValueChange={(s) => set("cadence", s as ScheduleInput["cadence"])}
              >
                <SelectTrigger id="schedule-cadence" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="weekly">Week</SelectItem>
                  <SelectItem value="monthly">Month</SelectItem>
                </SelectContent>
              </Select>
              <FieldError msg={errors.cadence} />
            </div>
            {v.cadence === "weekly" ? (
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="schedule-weekday">On</Label>
                <Select value={String(v.weekday)} onValueChange={(s) => set("weekday", Number(s))}>
                  <SelectTrigger id="schedule-weekday" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {WEEKDAYS.map((d, i) => (
                      <SelectItem key={d} value={String(i)}>
                        {d}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FieldError msg={errors.weekday} />
              </div>
            ) : (
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="schedule-day">On day</Label>
                <Select
                  value={String(v.dayOfMonth)}
                  onValueChange={(s) => set("dayOfMonth", Number(s))}
                >
                  <SelectTrigger id="schedule-day" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {DAYS.map((d) => (
                      <SelectItem key={d} value={String(d)}>
                        {d}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FieldError msg={errors.dayOfMonth} />
              </div>
            )}
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="schedule-hour">At</Label>
              <Select value={String(v.hour)} onValueChange={(s) => set("hour", Number(s))}>
                <SelectTrigger id="schedule-hour" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {HOURS.map((h) => (
                    <SelectItem key={h} value={String(h)}>
                      {hourLabel(h)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FieldError msg={errors.hour} />
            </div>
            {v.cadence === "monthly" && (
              <p className="text-muted-foreground text-xs sm:col-span-3">
                Days 1 to {MAX_DAY_OF_MONTH} only, so every month has the day.
              </p>
            )}
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="schedule-timezone">Timezone</Label>
            <Input
              id="schedule-timezone"
              list="schedule-timezones"
              value={v.timezone}
              autoComplete="off"
              spellCheck={false}
              aria-invalid={!!errors.timezone}
              onChange={(e) => set("timezone", e.target.value)}
            />
            <datalist id="schedule-timezones">
              {zones.map((z) => (
                <option key={z} value={z} />
              ))}
            </datalist>
            <FieldError msg={errors.timezone} />
            <p className="text-muted-foreground text-xs">
              The hour is local time there, so the report follows daylight saving time.
            </p>
          </div>

          <div className="flex flex-col gap-1.5">
            <Label>Send to</Label>
            {channels.length === 0 ? (
              <p className="text-muted-foreground text-sm">
                No channels yet: add one in <NotificationSettingsLink /> first.
              </p>
            ) : (
              <ChannelCheckList
                channels={channels}
                selected={v.channelIds}
                onToggle={(c) => set("channelIds", toggle(v.channelIds, c))}
              />
            )}
            <FieldError msg={errors.channelIds} />
          </div>

          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="accent-primary size-4"
              checked={v.enabled}
              onChange={(e) => set("enabled", e.target.checked)}
            />
            Enabled (send on schedule)
          </label>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={pending}>
              {pending && <Loader2 className="animate-spin" />}
              {schedule ? "Save" : "Create schedule"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
