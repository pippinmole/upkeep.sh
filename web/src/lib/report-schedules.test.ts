/// <reference types="bun" />

import { describe, expect, test } from "bun:test";
import {
  cadenceSummary,
  canonicalTimeZone,
  formatRunAt,
  NEXT_RUN_PENDING,
  type ScheduleInput,
  timeZoneOptions,
  validateSchedule,
} from "./report-schedules";

const CHANNEL = "0b8e7f52-1c3d-4e5f-8a9b-1c2d3e4f5a6b";

const weekly: ScheduleInput = {
  name: "Monday patch list",
  enabled: true,
  cadence: "weekly",
  weekday: 1,
  dayOfMonth: 1,
  hour: 9,
  timezone: "Europe/London",
  channelIds: [CHANNEL],
};

describe("cadenceSummary", () => {
  test("weekly", () => {
    expect(
      cadenceSummary({
        cadence: "weekly",
        weekday: 1,
        dayOfMonth: null,
        hour: 9,
        timezone: "Europe/London",
      }),
    ).toBe("Weekly, Monday 09:00 Europe/London");
    expect(
      cadenceSummary({
        cadence: "weekly",
        weekday: 0,
        dayOfMonth: null,
        hour: 23,
        timezone: "UTC",
      }),
    ).toBe("Weekly, Sunday 23:00 UTC");
  });

  test("monthly", () => {
    expect(
      cadenceSummary({
        cadence: "monthly",
        weekday: null,
        dayOfMonth: 1,
        hour: 0,
        timezone: "America/New_York",
      }),
    ).toBe("Monthly, day 1 00:00 America/New_York");
  });
});

describe("formatRunAt", () => {
  test("null is pending", () => {
    expect(formatRunAt(null, "Europe/London", NEXT_RUN_PENDING)).toBe("calculating…");
  });

  test("formats in the schedule's timezone", () => {
    // 08:00 UTC on a summer Monday is 09:00 BST in London.
    const s = formatRunAt("2026-10-05T08:00:00Z", "Europe/London");
    expect(s).toContain("09:00");
    expect(s).toContain("5 Oct 2026");
    expect(s).toContain("Mon");
    // After the October DST change, the same local hour is 09:00 GMT.
    expect(formatRunAt("2026-11-02T09:00:00Z", "Europe/London")).toContain("09:00");
  });

  test("unknown timezone falls back to UTC", () => {
    expect(formatRunAt("2026-10-05T08:00:00Z", "Nowhere/Special")).toContain("08:00");
  });
});

describe("canonicalTimeZone", () => {
  test("accepts IANA names", () => {
    expect(canonicalTimeZone("Europe/London")).toBe("Europe/London");
    expect(canonicalTimeZone(" Asia/Tokyo ")).toBe("Asia/Tokyo");
    expect(canonicalTimeZone("UTC")).toBe("UTC");
  });

  test("normalises case", () => {
    expect(canonicalTimeZone("utc")).toBe("UTC");
    expect(canonicalTimeZone("europe/london")).toBe("Europe/London");
  });

  test("refuses the rest", () => {
    for (const tz of ["", "Mars/Olympus_Mons", "+01:00", "-05:00", 42, null, "x".repeat(101)]) {
      expect(canonicalTimeZone(tz)).toBeNull();
    }
  });

  test("options include the current value and UTC", () => {
    const opts = timeZoneOptions("Europe/London");
    expect(opts).toContain("Europe/London");
    expect(opts).toContain("UTC");
    expect(opts).toEqual([...opts].sort());
  });
});

describe("validateSchedule", () => {
  test("weekly: keeps weekday, drops day of month", () => {
    const { schedule, fieldErrors } = validateSchedule({ ...weekly, name: "  Weekly  " });
    expect(fieldErrors).toEqual({});
    expect(schedule).toEqual({
      name: "Weekly",
      enabled: true,
      cadence: "weekly",
      weekday: 1,
      dayOfMonth: null,
      hour: 9,
      timezone: "Europe/London",
      channelIds: [CHANNEL],
    });
  });

  test("monthly: keeps day of month, drops weekday", () => {
    const { schedule } = validateSchedule({ ...weekly, cadence: "monthly", dayOfMonth: 28 });
    expect(schedule?.weekday).toBeNull();
    expect(schedule?.dayOfMonth).toBe(28);
  });

  test("day and hour ranges", () => {
    for (const weekday of [-1, 7, 1.5]) {
      expect(validateSchedule({ ...weekly, weekday }).fieldErrors.weekday).toBeDefined();
    }
    for (const dayOfMonth of [0, 29, 31]) {
      expect(
        validateSchedule({ ...weekly, cadence: "monthly", dayOfMonth }).fieldErrors.dayOfMonth,
      ).toBeDefined();
    }
    for (const hour of [-1, 24, 9.5]) {
      expect(validateSchedule({ ...weekly, hour }).fieldErrors.hour).toBeDefined();
    }
    expect(validateSchedule({ ...weekly, weekday: 0, hour: 0 }).schedule).toBeDefined();
    expect(validateSchedule({ ...weekly, weekday: 6, hour: 23 }).schedule).toBeDefined();
    // An out-of-range weekday doesn't matter on a monthly schedule.
    expect(
      validateSchedule({ ...weekly, cadence: "monthly", weekday: 99, dayOfMonth: 1 }).schedule,
    ).toBeDefined();
  });

  test("timezone", () => {
    expect(validateSchedule({ ...weekly, timezone: "Mars/Base" }).fieldErrors.timezone).toBe(
      "Pick a timezone from the list",
    );
    expect(validateSchedule({ ...weekly, timezone: "utc" }).schedule?.timezone).toBe("UTC");
  });

  test("name, cadence, channels, enabled", () => {
    expect(validateSchedule({ ...weekly, name: " " }).fieldErrors.name).toBeDefined();
    expect(validateSchedule({ ...weekly, name: "x".repeat(101) }).fieldErrors.name).toBeDefined();
    expect(
      validateSchedule({ ...weekly, cadence: "daily" as ScheduleInput["cadence"] }).fieldErrors
        .cadence,
    ).toBeDefined();
    expect(validateSchedule({ ...weekly, channelIds: [] }).fieldErrors.channelIds).toBe(
      "Pick at least one channel",
    );
    expect(validateSchedule({ ...weekly, channelIds: ["nope"] }).fieldErrors.channelIds).toBe(
      "Unknown channel",
    );
    expect(
      validateSchedule({ ...weekly, channelIds: [CHANNEL, CHANNEL] }).schedule?.channelIds,
    ).toEqual([CHANNEL]);
    expect(validateSchedule({ ...weekly, enabled: false }).schedule?.enabled).toBe(false);
    expect(validateSchedule(null).fieldErrors.name).toBeDefined();
  });
});
