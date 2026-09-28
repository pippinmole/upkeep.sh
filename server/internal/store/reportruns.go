package store

// Scheduled report runs (migration 0017, jobs/reports.go): which schedules
// are due, and storing a built report with its notification and
// deliveries. The reads a report is built from are in reports.go.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/notify"
	"github.com/pippinmole/upkeep.sh/server/internal/reports"
)

// reportsLock serializes report_due passes (pg_advisory_xact_lock key;
// alertingLock+1 is agent_health's).
const reportsLock = alertingLock + 2

// ReportSchedule is a report_schedules row.
type ReportSchedule struct {
	ID, UserID, Name string
	Enabled          bool
	Cadence          string // reports.CadenceWeekly | CadenceMonthly
	Weekday          *int   // weekly: 0 = Sunday
	DayOfMonth       *int   // monthly: 1-28
	Hour             int
	Timezone         string // IANA name
	NextRunAt        *time.Time
	LastRunAt        *time.Time
}

// Ref is the schedule as a snapshot records it.
func (r ReportSchedule) Ref() reports.ScheduleRef {
	return reports.ScheduleRef{ID: r.ID, Name: r.Name, Cadence: r.Cadence, Timezone: r.Timezone}
}

// NextRun is the schedule's first run strictly after `after`
// (reports.NextRun); an error for an invalid timezone or timing.
func (r ReportSchedule) NextRun(after time.Time) (time.Time, error) {
	return reports.NextRun(r.Cadence, r.Weekday, r.DayOfMonth, r.Hour, r.Timezone, after)
}

const reportScheduleCols = `s.id::text, s.user_id::text, s.name, s.enabled, s.cadence, s.weekday, s.day_of_month,
	s.hour, s.timezone, s.next_run_at, s.last_run_at`

func scanReportSchedule(row pgx.CollectableRow) (ReportSchedule, error) {
	var r ReportSchedule
	err := row.Scan(&r.ID, &r.UserID, &r.Name, &r.Enabled, &r.Cadence, &r.Weekday, &r.DayOfMonth,
		&r.Hour, &r.Timezone, &r.NextRunAt, &r.LastRunAt)
	return r, err
}

// LoadReportSchedule loads one schedule; ErrNotFound when it is gone.
func (s *Store) LoadReportSchedule(ctx context.Context, id string) (ReportSchedule, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+reportScheduleCols+` FROM report_schedules s WHERE s.id = $1`, id)
	if err != nil {
		return ReportSchedule{}, err
	}
	r, err := pgx.CollectExactlyOneRow(rows, scanReportSchedule)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

// InvalidSchedule is a schedule whose next run can't be computed (a
// timezone the worker doesn't know, or timing that fails the checks).
type InvalidSchedule struct {
	Schedule ReportSchedule
	Err      error
}

// DueReports is one report_due selection pass.
type DueReports struct {
	// Due: enabled schedules with next_run_at <= now, to run once each.
	Due []ReportSchedule
	// Computed: schedules whose NULL next_run_at was set (not run).
	Computed int
	// Invalid: schedules with a NULL next_run_at that couldn't be computed;
	// left NULL.
	Invalid []InvalidSchedule
}

// DueReportSchedules is report_due's selection pass, under reportsLock:
// enabled schedules whose next_run_at is NULL get it computed from now
// (and are not run: Next.js resets it to NULL on insert and when the
// timing changes, so the first run is the next occurrence, not "now");
// those with next_run_at <= now are returned to run. Running them happens
// outside this transaction (building a report takes a while); StoreReport
// re-checks next_run_at under a row lock, so a schedule runs once even if
// two passes overlap.
func (s *Store) DueReportSchedules(ctx context.Context, now time.Time) (DueReports, error) {
	var res DueReports
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(reportsLock)); err != nil {
		return res, err
	}
	rows, err := tx.Query(ctx, `
		SELECT `+reportScheduleCols+` FROM report_schedules s
		WHERE s.enabled AND (s.next_run_at IS NULL OR s.next_run_at <= $1) -- report_schedules_due_idx
		ORDER BY s.next_run_at NULLS FIRST, s.id
	`, now)
	if err != nil {
		return res, err
	}
	scheds, err := pgx.CollectRows(rows, scanReportSchedule)
	if err != nil {
		return res, err
	}
	for _, sc := range scheds {
		if sc.NextRunAt != nil {
			res.Due = append(res.Due, sc)
			continue
		}
		next, err := sc.NextRun(now)
		if err != nil {
			res.Invalid = append(res.Invalid, InvalidSchedule{sc, err})
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE report_schedules SET next_run_at = $2 WHERE id = $1 AND next_run_at IS NULL`,
			sc.ID, next); err != nil {
			return res, err
		}
		res.Computed++
	}
	return res, tx.Commit(ctx)
}

// NewReport is a built report to store.
type NewReport struct {
	Schedule ReportSchedule
	Trigger  string // reports.TriggerScheduled | TriggerManual
	Snapshot reports.Snapshot
	// PreviousID is the report Snapshot was compared with (nil: none). If
	// the schedule's latest report is another one by the time the report
	// is stored, StoreReport fails with ErrReportConflict.
	PreviousID *string
	// Now is generated_at, period_end (Snapshot.Period.End) and last_run_at.
	Now time.Time

	// Scheduled runs: the run happens only if the schedule is enabled and
	// its next_run_at is still ExpectNextRunAt (another pass didn't run it
	// first, the user didn't change its timing), and next_run_at becomes
	// NextRunAt.
	ExpectNextRunAt time.Time
	NextRunAt       time.Time
	// Manual runs: skipped when a manual report of the schedule was
	// generated at or after ManualSince (the job's creation), i.e. this job
	// already ran and is being retried. Zero = no check.
	ManualSince time.Time
}

// StoredReport is what StoreReport did.
type StoredReport struct {
	ReportID       string
	NotificationID string
	Deliveries     int
	// Skipped says why nothing was stored ("" = stored).
	Skipped string
}

// ErrReportConflict: another report of the schedule was stored while this
// one was being built, so its comparison is against the wrong previous
// report. Retrying builds it again.
var ErrReportConflict = errors.New("another report of this schedule was stored meanwhile")

// StoreReport stores a built report in one transaction: the reports row,
// the schedule's last_run_at (and next_run_at for a scheduled run), a
// 'report' notification pointing at it, one pending delivery per enabled
// channel of the schedule, and their alert_deliver jobs (enqueue). A
// schedule without enabled channels still gets its report stored (the
// dashboard lists it) with no deliveries.
func (s *Store) StoreReport(ctx context.Context, r NewReport, enqueue EnqueueDeliveries) (StoredReport, error) {
	var res StoredReport
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx)

	var (
		nextRunAt *time.Time
		enabled   bool
	)
	err = tx.QueryRow(ctx, `SELECT next_run_at, enabled FROM report_schedules WHERE id = $1 FOR UPDATE`,
		r.Schedule.ID).Scan(&nextRunAt, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		res.Skipped = "schedule was deleted"
		return res, nil
	}
	if err != nil {
		return res, err
	}
	switch r.Trigger {
	case reports.TriggerScheduled:
		switch {
		case !enabled:
			res.Skipped = "schedule was disabled"
		case nextRunAt == nil || !nextRunAt.Equal(r.ExpectNextRunAt):
			res.Skipped = "already run, or its timing changed"
		}
	case reports.TriggerManual:
		if !r.ManualSince.IsZero() {
			var done bool
			if err := tx.QueryRow(ctx, `
				SELECT EXISTS (SELECT 1 FROM reports WHERE schedule_id = $1 AND trigger = 'manual' AND generated_at >= $2)
			`, r.Schedule.ID, r.ManualSince).Scan(&done); err != nil {
				return res, err
			}
			if done {
				res.Skipped = "already sent"
			}
		}
	default:
		return res, fmt.Errorf("unknown report trigger %q", r.Trigger)
	}
	if res.Skipped != "" {
		return res, nil
	}
	var latest *string
	if err := tx.QueryRow(ctx, `
		SELECT id::text FROM reports WHERE schedule_id = $1 ORDER BY generated_at DESC, id DESC LIMIT 1
	`, r.Schedule.ID).Scan(&latest); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return res, err
	}
	if (latest == nil) != (r.PreviousID == nil) || (latest != nil && *latest != *r.PreviousID) {
		return res, ErrReportConflict
	}

	snap, err := json.Marshal(r.Snapshot)
	if err != nil {
		return res, err
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO reports (schedule_id, user_id, generated_at, period_start, period_end, ranking_version,
		                     snapshot, previous_report_id, trigger)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id::text
	`, r.Schedule.ID, r.Schedule.UserID, r.Now, r.Snapshot.Period.Start, r.Snapshot.Period.End,
		r.Snapshot.RankingVersion, snap, r.PreviousID, r.Trigger).Scan(&res.ReportID); err != nil {
		return res, fmt.Errorf("insert report: %w", err)
	}
	if r.Trigger == reports.TriggerScheduled {
		_, err = tx.Exec(ctx, `UPDATE report_schedules SET last_run_at = $2, next_run_at = $3 WHERE id = $1`,
			r.Schedule.ID, r.Now, r.NextRunAt)
	} else {
		_, err = tx.Exec(ctx, `UPDATE report_schedules SET last_run_at = $2 WHERE id = $1`, r.Schedule.ID, r.Now)
	}
	if err != nil {
		return res, err
	}

	// The notification keeps only the report's id: alert_deliver loads the
	// snapshot from reports (notifications.report_id) at send time.
	n := notify.Notification{
		Version: notify.PayloadVersion, Kind: notify.KindReport, CreatedAt: r.Now,
		Summary: reports.Title(r.Snapshot), Events: []notify.Event{},
		Report: &notify.Report{ID: res.ReportID},
	}
	if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&n.ID); err != nil {
		return res, err
	}
	payload, err := json.Marshal(n)
	if err != nil {
		return res, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO notifications (id, user_id, kind, event_count, summary, payload, report_id, created_at)
		VALUES ($1, $2, $3, 0, $4, $5, $6, $7)
	`, n.ID, r.Schedule.UserID, notify.KindReport, n.Summary, payload, res.ReportID, r.Now); err != nil {
		return res, fmt.Errorf("insert report notification: %w", err)
	}
	res.NotificationID = n.ID
	rows, err := tx.Query(ctx, `
		INSERT INTO notification_deliveries (user_id, notification_id, channel_id, channel_name, channel_type, created_at, updated_at)
		SELECT c.user_id, $2, c.id, c.name, c.type, $3, $3
		FROM report_schedule_channels sc
		JOIN notification_channels c ON c.id = sc.channel_id AND c.enabled
		WHERE sc.schedule_id = $1
		ORDER BY c.name, c.id
		RETURNING id::text
	`, r.Schedule.ID, n.ID, r.Now)
	if err != nil {
		return res, err
	}
	deliveries, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return res, fmt.Errorf("insert report deliveries: %w", err)
	}
	res.Deliveries = len(deliveries)
	if len(deliveries) > 0 && enqueue != nil {
		if err := enqueue(ctx, tx, deliveries); err != nil {
			return res, err
		}
	}
	return res, tx.Commit(ctx)
}

// ReportURL is the dashboard page of a stored report
// (web: /dashboard/reports/<id>); "" when base (SW_DASHBOARD_URL) is unset.
func ReportURL(base, reportID string) string {
	base = strings.TrimRight(base, "/")
	if base == "" {
		return ""
	}
	return base + "/dashboard/reports/" + url.PathEscape(reportID)
}
