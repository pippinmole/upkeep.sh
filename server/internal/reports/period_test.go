package reports

import (
	"testing"
	"time"
)

func TestPeriodFor(t *testing.T) {
	utc := func(s string) time.Time {
		t.Helper()
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	prev := utc("2026-09-21T07:00:03Z")
	for _, c := range []struct {
		name, cadence, tz string
		prev              *time.Time
		now, want         string
	}{
		{"previous report", CadenceWeekly, "Europe/London", &prev, "2026-09-28T07:00:04Z", "2026-09-21T07:00:03Z"},
		{"weekly", CadenceWeekly, "UTC", nil, "2026-09-28T07:00:00Z", "2026-09-21T07:00:00Z"},
		// London leaves BST on 25 Oct 2026: 08:00 local both weeks, so
		// 7 days + 1 hour of UTC.
		{"weekly across DST", CadenceWeekly, "Europe/London", nil, "2026-10-26T08:00:00Z", "2026-10-19T07:00:00Z"},
		{"monthly", CadenceMonthly, "Europe/London", nil, "2026-09-01T07:00:00Z", "2026-08-01T07:00:00Z"},
		{"monthly clamps", CadenceMonthly, "UTC", nil, "2026-03-31T09:00:00Z", "2026-02-28T09:00:00Z"},
		{"monthly over the year", CadenceMonthly, "America/New_York", nil, "2026-01-15T14:00:00Z", "2025-12-15T14:00:00Z"},
	} {
		p, err := PeriodFor(c.cadence, c.tz, c.prev, utc(c.now))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !p.Start.Equal(utc(c.want)) || !p.End.Equal(utc(c.now)) || p.Start.Location() != time.UTC {
			t.Errorf("%s: period = %v .. %v, want start %s", c.name, p.Start, p.End, c.want)
		}
	}
	if _, err := PeriodFor(CadenceWeekly, "Not/AZone", nil, time.Now()); err == nil {
		t.Error("bad timezone accepted")
	}
	if _, err := PeriodFor("daily", "UTC", nil, time.Now()); err == nil {
		t.Error("bad cadence accepted")
	}
}
