package reports

import (
	"testing"
	"time"
)

func TestNextRun(t *testing.T) {
	utc := func(s string) time.Time {
		t.Helper()
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	day := func(n int) *int { return &n }
	for _, c := range []struct {
		name, cadence string
		weekday, dom  *int
		hour          int
		tz            string
		after, want   string
	}{
		// Monday 07:00 in London (BST until 25 Oct 2026).
		{"weekly later today", CadenceWeekly, day(1), nil, 7, "Europe/London", "2026-09-28T05:00:00Z", "2026-09-28T06:00:00Z"},
		{"weekly exactly on the run", CadenceWeekly, day(1), nil, 7, "Europe/London", "2026-09-28T06:00:00Z", "2026-10-05T06:00:00Z"},
		{"weekly just after", CadenceWeekly, day(1), nil, 7, "Europe/London", "2026-09-28T06:00:01Z", "2026-10-05T06:00:00Z"},
		{"weekly across fall back keeps local hour", CadenceWeekly, day(1), nil, 7, "Europe/London", "2026-10-19T06:00:00Z", "2026-10-26T07:00:00Z"},
		{"weekly across spring forward keeps local hour", CadenceWeekly, day(1), nil, 7, "Europe/London", "2026-03-23T07:00:00Z", "2026-03-30T06:00:00Z"},
		// London springs forward 01:00 GMT -> 02:00 BST on 29 Mar 2026:
		// Sunday 01:00 doesn't exist and runs when the clocks go forward.
		{"London gap", CadenceWeekly, day(0), nil, 1, "Europe/London", "2026-03-28T12:00:00Z", "2026-03-29T01:00:00Z"},
		{"London after gap", CadenceWeekly, day(0), nil, 1, "Europe/London", "2026-03-29T01:00:00Z", "2026-04-05T00:00:00Z"},
		// London falls back 02:00 BST -> 01:00 GMT on 25 Oct 2026: Sunday
		// 01:00 happens at 00:00Z and 01:00Z; the first one, once.
		{"London overlap first occurrence", CadenceWeekly, day(0), nil, 1, "Europe/London", "2026-10-24T12:00:00Z", "2026-10-25T00:00:00Z"},
		{"London overlap not twice", CadenceWeekly, day(0), nil, 1, "Europe/London", "2026-10-25T00:00:00Z", "2026-11-01T01:00:00Z"},
		// New York springs forward 02:00 EST -> 03:00 EDT on 8 Mar 2026.
		{"New York gap", CadenceWeekly, day(0), nil, 2, "America/New_York", "2026-03-07T12:00:00Z", "2026-03-08T07:00:00Z"},
		{"New York hour before gap", CadenceWeekly, day(0), nil, 1, "America/New_York", "2026-03-07T12:00:00Z", "2026-03-08T06:00:00Z"},
		{"New York hour after gap", CadenceWeekly, day(0), nil, 3, "America/New_York", "2026-03-07T12:00:00Z", "2026-03-08T07:00:00Z"},
		// New York falls back 02:00 EDT -> 01:00 EST on 1 Nov 2026.
		{"New York overlap first occurrence", CadenceWeekly, day(0), nil, 1, "America/New_York", "2026-10-31T12:00:00Z", "2026-11-01T05:00:00Z"},
		{"New York overlap not twice", CadenceWeekly, day(0), nil, 1, "America/New_York", "2026-11-01T05:00:00Z", "2026-11-08T06:00:00Z"},
		// The local date, not the UTC date, picks the day.
		{"local date ahead of UTC", CadenceWeekly, day(1), nil, 8, "Asia/Tokyo", "2026-09-27T22:00:00Z", "2026-09-27T23:00:00Z"},
		{"weekly over the year", CadenceWeekly, day(5), nil, 23, "Europe/London", "2026-12-31T23:30:00Z", "2027-01-01T23:00:00Z"},

		{"monthly day 28", CadenceMonthly, nil, day(28), 9, "UTC", "2026-02-27T00:00:00Z", "2026-02-28T09:00:00Z"},
		{"monthly day 28 exactly on the run", CadenceMonthly, nil, day(28), 9, "UTC", "2026-02-28T09:00:00Z", "2026-03-28T09:00:00Z"},
		{"monthly over the year", CadenceMonthly, nil, day(15), 14, "America/New_York", "2026-12-20T00:00:00Z", "2027-01-15T19:00:00Z"},
		{"monthly in GMT", CadenceMonthly, nil, day(1), 7, "Europe/London", "2026-10-15T00:00:00Z", "2026-11-01T07:00:00Z"},
		{"monthly in BST", CadenceMonthly, nil, day(1), 7, "Europe/London", "2026-03-15T00:00:00Z", "2026-04-01T06:00:00Z"},
		{"monthly exactly on the run", CadenceMonthly, nil, day(1), 7, "Europe/London", "2026-11-01T07:00:00Z", "2026-12-01T07:00:00Z"},
		{"monthly in a gap", CadenceMonthly, nil, day(8), 2, "America/New_York", "2026-03-01T00:00:00Z", "2026-03-08T07:00:00Z"},
	} {
		got, err := NextRun(c.cadence, c.weekday, c.dom, c.hour, c.tz, utc(c.after))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !got.Equal(utc(c.want)) {
			t.Errorf("%s: NextRun(after %s) = %s, want %s", c.name, c.after, got.UTC().Format(time.RFC3339), c.want)
		}
		if !got.After(utc(c.after)) {
			t.Errorf("%s: %s is not after %s", c.name, got, c.after)
		}
	}

	now := time.Now()
	for _, c := range []struct {
		name, cadence string
		weekday, dom  *int
		hour          int
		tz            string
	}{
		{"bad timezone", CadenceWeekly, day(1), nil, 7, "Not/AZone"},
		{"bad cadence", "daily", nil, nil, 7, "UTC"},
		{"weekly without weekday", CadenceWeekly, nil, day(1), 7, "UTC"},
		{"weekday out of range", CadenceWeekly, day(7), nil, 7, "UTC"},
		{"monthly day 29", CadenceMonthly, nil, day(29), 7, "UTC"},
		{"hour out of range", CadenceMonthly, nil, day(1), 24, "UTC"},
	} {
		if _, err := NextRun(c.cadence, c.weekday, c.dom, c.hour, c.tz, now); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

// Every week of a year in zones with DST lands on the local hour (or just
// after a gap), strictly after the previous run, about a week apart.
func TestNextRunChain(t *testing.T) {
	weekday := 0
	for _, tz := range []string{"Europe/London", "America/New_York", "Australia/Sydney", "UTC"} {
		loc, _ := time.LoadLocation(tz)
		for _, hour := range []int{0, 1, 2, 3, 12, 23} {
			prev := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			for range 60 {
				next, err := NextRun(CadenceWeekly, &weekday, nil, hour, tz, prev)
				if err != nil {
					t.Fatal(err)
				}
				l := next.In(loc)
				if l.Weekday() != time.Sunday || (l.Hour() != hour && l.Hour() != hour+1) {
					t.Fatalf("%s %02d:00: next run %s", tz, hour, l)
				}
				if d := next.Sub(prev); prev.Year() == 2026 && prev.Month() > 1 && (d < 6*24*time.Hour || d > 8*24*time.Hour) {
					t.Fatalf("%s %02d:00: %s after %s", tz, hour, next, prev)
				}
				prev = next
			}
		}
	}
}
