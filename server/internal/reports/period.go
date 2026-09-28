package reports

import (
	"fmt"
	"time"
	// Schedule timezones are IANA names; the server image (alpine, no
	// tzdata package) has no zoneinfo, so embed it.
	_ "time/tzdata"
)

// PeriodFor is what a report generated at now covers (reports.period_start
// / period_end): from the previous report's generated_at (prevGeneratedAt,
// nil when the schedule has none) to now. For a schedule's first report it
// is one nominal period back, in the schedule's timezone so DST doesn't
// shift it: 7 calendar days for weekly, one calendar month for monthly
// (clamped to the end of a shorter month: 31 March -> 28/29 February).
func PeriodFor(cadence, timezone string, prevGeneratedAt *time.Time, now time.Time) (Period, error) {
	end := now.UTC()
	if prevGeneratedAt != nil {
		start := prevGeneratedAt.UTC()
		if start.After(end) {
			start = end // clock skew between writers; keep period_start <= period_end
		}
		return Period{Start: start, End: end}, nil
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return Period{}, fmt.Errorf("schedule timezone %q: %w", timezone, err)
	}
	local := now.In(loc)
	var start time.Time
	switch cadence {
	case CadenceWeekly:
		start = local.AddDate(0, 0, -7)
	case CadenceMonthly:
		y, m, d := local.Date()
		first := time.Date(y, m-1, 1, 0, 0, 0, 0, loc) // normalises January -> December
		last := first.AddDate(0, 1, -1).Day()
		start = time.Date(first.Year(), first.Month(), min(d, last),
			local.Hour(), local.Minute(), local.Second(), local.Nanosecond(), loc)
	default:
		return Period{}, fmt.Errorf("unknown cadence %q", cadence)
	}
	return Period{Start: start.UTC(), End: end}, nil
}
