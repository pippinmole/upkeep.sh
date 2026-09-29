// Report schedules (migration 0017, docs/tasks/phase-1-7-reports.md): the
// pure parts shared by the Reports page schedule dialog and the
// server actions, which validate everything again. Client-safe: no
// database imports.
//
// Weekday 0 = Sunday .. 6 = Saturday (like JS getDay and Go time.Weekday).
// day_of_month stops at 28 so every month has the day. The hour is local
// time in the schedule's IANA timezone.

import type { ReportCadence } from "@/lib/report-snapshot";

export const WEEKDAYS = [
  "Sunday",
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
] as const;

export const MAX_DAY_OF_MONTH = 28;

export type ScheduleTiming = {
  cadence: ReportCadence;
  /** Weekly only; null for monthly. */
  weekday: number | null;
  /** Monthly only; null for weekly. */
  dayOfMonth: number | null;
  hour: number;
  timezone: string;
};

export type ScheduleInput = {
  name: string;
  enabled: boolean;
  cadence: ReportCadence;
  weekday: number;
  dayOfMonth: number;
  hour: number;
  timezone: string;
  channelIds: string[];
};

export type CleanSchedule = ScheduleTiming & {
  name: string;
  enabled: boolean;
  channelIds: string[];
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// "09:00"
export function hourLabel(hour: number): string {
  return `${String(hour).padStart(2, "0")}:00`;
}

// "Weekly, Monday 09:00 Europe/London", "Monthly, day 1 09:00 Europe/London".
export function cadenceSummary(t: ScheduleTiming): string {
  const at = `${hourLabel(t.hour)} ${t.timezone}`;
  if (t.cadence === "weekly") {
    return `Weekly, ${WEEKDAYS[t.weekday ?? -1] ?? "unknown day"} ${at}`;
  }
  return `Monthly, day ${t.dayOfMonth ?? "?"} ${at}`;
}

/**
 * The canonical form of an IANA timezone name Intl accepts ("utc" → "UTC"),
 * or null. The worker loads it with Go's time.LoadLocation, which is
 * case-sensitive, hence storing Intl's spelling rather than the input.
 * Offsets ("+01:00") are refused: the schedule must follow DST.
 */
export function canonicalTimeZone(tz: unknown): string | null {
  if (typeof tz !== "string") return null;
  const s = tz.trim();
  if (s === "" || s.length > 100 || /^[+-]/.test(s)) return null;
  try {
    return new Intl.DateTimeFormat("en-US", { timeZone: s }).resolvedOptions().timeZone;
  } catch {
    return null;
  }
}

/** The timezones offered in the dialog, with `current` included if missing. */
export function timeZoneOptions(current: string): string[] {
  let zones: string[] = [];
  try {
    zones = Intl.supportedValuesOf("timeZone");
  } catch {
    zones = [];
  }
  const all = new Set(zones);
  all.add("UTC");
  if (current) all.add(current);
  return [...all].sort();
}

/** The browser's timezone, falling back to UTC. */
export function browserTimeZone(): string {
  try {
    return canonicalTimeZone(Intl.DateTimeFormat().resolvedOptions().timeZone) ?? "UTC";
  } catch {
    return "UTC";
  }
}

const nextRunFormats = new Map<string, Intl.DateTimeFormat>();

function nextRunFormat(timeZone: string): Intl.DateTimeFormat {
  let f = nextRunFormats.get(timeZone);
  if (!f) {
    const opts: Intl.DateTimeFormatOptions = {
      weekday: "short",
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      timeZoneName: "short",
    };
    try {
      f = new Intl.DateTimeFormat("en-GB", { ...opts, timeZone });
    } catch {
      f = new Intl.DateTimeFormat("en-GB", { ...opts, timeZone: "UTC" });
    }
    nextRunFormats.set(timeZone, f);
  }
  return f;
}

/**
 * Whether saving `next` over the stored `prev` must reset next_run_at to
 * NULL so the worker recomputes it from now: when the timing changes, and
 * when a disabled schedule is enabled (its stored next_run_at may be long
 * past, and a re-enabled schedule mustn't fire at once). Disabling, or
 * saving an enabled schedule with the same timing, keeps it.
 */
export function resetsNextRun(
  prev: ScheduleTiming & { enabled: boolean },
  next: ScheduleTiming & { enabled: boolean },
): boolean {
  if (!prev.enabled && next.enabled) return true;
  return (
    prev.cadence !== next.cadence ||
    prev.weekday !== next.weekday ||
    prev.dayOfMonth !== next.dayOfMonth ||
    prev.hour !== next.hour ||
    prev.timezone !== next.timezone
  );
}

/**
 * A run time in the schedule's own timezone ("Mon, 5 Oct 2026, 09:00 BST"),
 * which is what "Monday 09:00" meant to whoever set it up. next_run_at is
 * NULL until the worker computes it (within a minute of a change).
 */
export function formatRunAt(iso: string | null, timeZone: string, pending = "—"): string {
  if (!iso) return pending;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? pending : nextRunFormat(timeZone).format(d);
}

export const NEXT_RUN_PENDING = "calculating…";

function intIn(v: unknown, min: number, max: number): number | null {
  const n = typeof v === "number" ? v : typeof v === "string" && v.trim() !== "" ? Number(v) : NaN;
  return Number.isInteger(n) && n >= min && n <= max ? n : null;
}

/**
 * Everything but channel ownership (the server action checks that against
 * the database). Returns the cleaned schedule or per-field errors keyed like
 * ScheduleInput.
 */
export function validateSchedule(input: Partial<ScheduleInput> | null | undefined): {
  schedule?: CleanSchedule;
  fieldErrors: Record<string, string>;
} {
  const errors: Record<string, string> = {};
  const v = input ?? {};
  const name = typeof v.name === "string" ? v.name.trim() : "";
  if (name.length < 1 || name.length > 100) errors.name = "Name is required (up to 100 characters)";

  const cadence = v.cadence === "weekly" || v.cadence === "monthly" ? v.cadence : null;
  if (!cadence) errors.cadence = "Pick weekly or monthly";
  const weekday = cadence === "weekly" ? intIn(v.weekday, 0, 6) : null;
  if (cadence === "weekly" && weekday === null) errors.weekday = "Pick a day of the week";
  const dayOfMonth = cadence === "monthly" ? intIn(v.dayOfMonth, 1, MAX_DAY_OF_MONTH) : null;
  if (cadence === "monthly" && dayOfMonth === null) {
    errors.dayOfMonth = `Pick a day from 1 to ${MAX_DAY_OF_MONTH}`;
  }
  const hour = intIn(v.hour, 0, 23);
  if (hour === null) errors.hour = "Pick an hour from 0 to 23";
  const timezone = canonicalTimeZone(v.timezone);
  if (!timezone) errors.timezone = "Pick a timezone from the list";

  const channelIds = Array.isArray(v.channelIds)
    ? [...new Set(v.channelIds.filter((id): id is string => typeof id === "string"))]
    : [];
  if (channelIds.length === 0) errors.channelIds = "Pick at least one channel";
  else if (!channelIds.every((id) => UUID_RE.test(id))) errors.channelIds = "Unknown channel";

  if (Object.keys(errors).length > 0) return { fieldErrors: errors };
  return {
    fieldErrors: {},
    schedule: {
      name,
      enabled: v.enabled === true,
      cadence: cadence!,
      weekday,
      dayOfMonth,
      hour: hour!,
      timezone: timezone!,
      channelIds,
    },
  };
}
