package reports

import (
	"errors"
	"fmt"
	"time"
)

// NextRun is a schedule's first run strictly after `after`: the hour
// (0-23, local wall clock in the IANA timezone tz) on the weekday
// (weekly; 0 = Sunday, like time.Weekday) or day of the month (monthly;
// 1-28) given by cadence. report_due stores it in
// report_schedules.next_run_at: computed from now when it is NULL (the
// schedule is then not run on that pass), and from the run's own time
// after a run, so a run missed while the worker was down happens once
// when it comes back rather than once per missed period.
//
// DST: the hour is local time, so a DST change moves the UTC instant, not
// the local hour.
//   - A local time that doesn't exist (spring forward, e.g. 01:00 in
//     Europe/London on the last Sunday of March) runs at the first valid
//     instant after the gap, which is when the clocks go forward (02:00
//     BST there).
//   - A local time that happens twice (fall back, e.g. 01:00 in
//     America/New_York on the first Sunday of November) runs at the first
//     occurrence (01:00 EDT), once.
func NextRun(cadence string, weekday, dayOfMonth *int, hour int, tz string, after time.Time) (time.Time, error) {
	if hour < 0 || hour > 23 {
		return time.Time{}, fmt.Errorf("hour %d out of range", hour)
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.Time{}, fmt.Errorf("schedule timezone %q: %w", tz, err)
	}
	y, m, d := after.In(loc).Date()
	switch cadence {
	case CadenceWeekly:
		if weekday == nil || *weekday < 0 || *weekday > 6 {
			return time.Time{}, errors.New("weekly schedule needs a weekday 0-6")
		}
		// Today's slot may have passed; a week and a day covers every case.
		for i := range 9 {
			day := time.Date(y, m, d+i, 0, 0, 0, 0, time.UTC) // calendar arithmetic only
			if int(day.Weekday()) != *weekday {
				continue
			}
			if t := wallClock(day.Year(), day.Month(), day.Day(), hour, loc); t.After(after) {
				return t, nil
			}
		}
	case CadenceMonthly:
		if dayOfMonth == nil || *dayOfMonth < 1 || *dayOfMonth > 28 {
			return time.Time{}, errors.New("monthly schedule needs a day of month 1-28")
		}
		for i := range 3 {
			// Day 28 at most, so the date never spills into the next month.
			day := time.Date(y, m+time.Month(i), *dayOfMonth, 0, 0, 0, 0, time.UTC)
			if t := wallClock(day.Year(), day.Month(), day.Day(), hour, loc); t.After(after) {
				return t, nil
			}
		}
	default:
		return time.Time{}, fmt.Errorf("unknown cadence %q", cadence)
	}
	return time.Time{}, errors.New("no next run found") // unreachable for valid input
}

// wallClock is the instant local time y-m-d h:00 in loc happens: the
// first occurrence when it happens twice (fall back), and the end of the
// gap when it doesn't happen at all (spring forward). time.Date leaves
// both cases unspecified ("the choice of time zone, and therefore the
// time, is not guaranteed"), so the candidates are worked out from the
// zone offsets in effect around that date.
func wallClock(y int, m time.Month, d, h int, loc *time.Location) time.Time {
	naive := time.Date(y, m, d, h, 0, 0, 0, time.UTC)
	var (
		best  time.Time
		found bool
	)
	for _, probe := range []time.Duration{-36 * time.Hour, 0, 36 * time.Hour} {
		_, off := naive.Add(probe).In(loc).Zone()
		t := naive.Add(-time.Duration(off) * time.Second)
		lt := t.In(loc)
		if lt.Year() == y && lt.Month() == m && lt.Day() == d && lt.Hour() == h && lt.Minute() == 0 {
			if !found || t.Before(best) {
				best, found = t, true
			}
		}
	}
	if found {
		return best
	}
	// In a gap: read with the offset from before the change, the wall time
	// is already past the transition, and the zone in effect there starts
	// at the transition itself, the first valid instant after the gap.
	_, off := naive.Add(-36 * time.Hour).In(loc).Zone()
	t := naive.Add(-time.Duration(off) * time.Second)
	if start, _ := t.In(loc).ZoneBounds(); !start.IsZero() && start.After(t.Add(-24*time.Hour)) {
		return start
	}
	return t
}
