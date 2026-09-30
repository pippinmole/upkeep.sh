package jobs

// Scheduled report jobs (docs/ARCHITECTURE.md "Reports"), queue "alerts":
//
//	report_due       (every 1m) advisory-locked selection: NULL next_run_at
//	                 -> computed from now (not run); next_run_at <= now ->
//	                 runReport once, next_run_at -> first occurrence after now
//	report_send_now  "Send now" in the dashboard (web inserts the job with
//	                 plain SQL): runReport for one schedule, trigger manual,
//	                 next_run_at untouched
//	runReport        read tx (REPEATABLE READ): previous report + inputs ->
//	                 reports.Build + reports.Compare -> one write tx:
//	                 reports row, last_run_at (+ next_run_at), a 'report'
//	                 notification, a delivery per enabled channel and their
//	                 alert_deliver jobs (InsertTx)
//
// Delivery is the alerting path's: alert_deliver loads the stored snapshot
// through notifications.report_id.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/riverqueue/river"

	"github.com/pippinmole/upkeep.sh/server/internal/reports"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

// ReportDueArgs runs the report schedules that are due.
type ReportDueArgs struct{}

func (ReportDueArgs) Kind() string { return "report_due" }
func (ReportDueArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueAlerts, MaxAttempts: 3, UniqueOpts: uniqueWhileActive}
}

// ReportSendNowArgs runs one schedule's report now ("Send now"). The
// dashboard inserts this job with plain SQL (web/src/lib/river.ts), so keep
// the kind, args shape, queue and max attempts stable.
type ReportSendNowArgs struct {
	ScheduleID string `json:"schedule_id"`
}

func (ReportSendNowArgs) Kind() string { return "report_send_now" }
func (ReportSendNowArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueAlerts, MaxAttempts: 3}
}

// reportTimeout bounds one report job: a report's reads are a handful of
// queries over one user's estate.
const reportTimeout = 5 * time.Minute

// runReport builds one report of sched generated at now and stores it
// (store.StoreReport, which also queues its deliveries). For a scheduled
// run, next_run_at becomes nextRun, provided it is still expect (see
// store.NewReport); for a manual one, manualSince guards against a retried
// job sending twice.
func runReport(ctx context.Context, st *store.Store, sched store.ReportSchedule, trigger string, now time.Time,
	expect, nextRun, manualSince time.Time) (store.StoredReport, error) {
	tx, err := st.BeginReportRead(ctx)
	if err != nil {
		return store.StoredReport{}, err
	}
	defer tx.Rollback(ctx)
	prev, err := st.LatestReport(ctx, tx, sched.ID)
	if err != nil {
		return store.StoredReport{}, err
	}
	var prevAt *time.Time
	if prev != nil {
		prevAt = &prev.GeneratedAt
	}
	period, err := reports.PeriodFor(sched.Cadence, sched.Timezone, prevAt, now)
	if err != nil {
		return store.StoredReport{}, err
	}
	in, err := st.LoadReportInputs(ctx, tx, sched.WorkspaceID, period)
	if err != nil {
		return store.StoredReport{}, err
	}
	_ = tx.Rollback(ctx) // read-only; done with the snapshot of the database

	snap := reports.Build(in, sched.Ref(), trigger, period, now)
	r := store.NewReport{
		Schedule: sched, Trigger: trigger, Now: now,
		ExpectNextRunAt: expect, NextRunAt: nextRun, ManualSince: manualSince,
	}
	if prev != nil {
		snap.Changes = reports.Compare(&prev.Snapshot, prev.ID, snap)
		r.PreviousID = &prev.ID
	}
	r.Snapshot = snap
	return st.StoreReport(ctx, r, enqueueDeliveries)
}

// reportNow is the clock for a report: microsecond precision, what
// Postgres stores, so generated_at, period_end and the snapshot's
// timestamps are the same instant, and the next report's period_start
// (the stored generated_at) matches this one's end exactly.
func reportNow(cfg AlertingConfig) time.Time { return cfg.now().Truncate(time.Microsecond) }

type ReportDueWorker struct {
	river.WorkerDefaults[ReportDueArgs]
	Store *store.Store
	Cfg   AlertingConfig

	// warned: schedules whose invalid timing was already logged, by id
	// (with the timezone that failed), so a bad schedule is logged once per
	// process rather than on every pass.
	mu     sync.Mutex
	warned map[string]string
}

func (w *ReportDueWorker) Timeout(*river.Job[ReportDueArgs]) time.Duration { return reportTimeout }

// warnInvalid logs a schedule whose next run can't be computed, once per
// schedule and timezone. The schedule is left as it is (Next.js validates
// the timezone on write, so this means the worker's tzdata lacks a name
// the browser has, or the row was edited by hand): it stays NULL or due
// and is retried every pass, which is one indexed query, until the user
// fixes it.
func (w *ReportDueWorker) warnInvalid(sched store.ReportSchedule, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.warned == nil {
		w.warned = map[string]string{}
	}
	if w.warned[sched.ID] == sched.Timezone {
		return
	}
	w.warned[sched.ID] = sched.Timezone
	log.Printf("report_due: schedule %s (%q) skipped: %v", sched.ID, sched.Name, err)
}

func (w *ReportDueWorker) Work(ctx context.Context, _ *river.Job[ReportDueArgs]) error {
	now := reportNow(w.Cfg)
	due, err := w.Store.DueReportSchedules(ctx, now)
	if err != nil {
		return err
	}
	for _, inv := range due.Invalid {
		w.warnInvalid(inv.Schedule, inv.Err)
	}
	var ran, deliveries int
	for _, sched := range due.Due {
		// The next run is the first occurrence after now, not after the
		// missed one: a schedule the worker missed for weeks runs once.
		next, err := sched.NextRun(now)
		if err != nil {
			w.warnInvalid(sched, err)
			continue
		}
		res, err := runReport(ctx, w.Store, sched, reports.TriggerScheduled, now, *sched.NextRunAt, next, time.Time{})
		if err != nil {
			// Left due: the next pass (a minute later) tries again.
			log.Printf("report_due: schedule %s: %v", sched.ID, err)
			continue
		}
		if res.Skipped == "" {
			ran++
			deliveries += res.Deliveries
		}
	}
	if due.Computed+ran > 0 {
		log.Printf("report_due: %d next runs computed, %d reports, %d deliveries", due.Computed, ran, deliveries)
	}
	return nil
}

type ReportSendNowWorker struct {
	river.WorkerDefaults[ReportSendNowArgs]
	Store *store.Store
	Cfg   AlertingConfig
}

func (w *ReportSendNowWorker) Timeout(*river.Job[ReportSendNowArgs]) time.Duration {
	return reportTimeout
}

// Work runs a manual report. The schedule's owner is the only one who can
// see its "Send now" button, and the args carry nothing else to check, so
// a schedule that exists is run, disabled or not: disabling stops the
// schedule, while "Send now" is an explicit request for one report.
func (w *ReportSendNowWorker) Work(ctx context.Context, job *river.Job[ReportSendNowArgs]) error {
	sched, err := w.Store.LoadReportSchedule(ctx, job.Args.ScheduleID)
	if errors.Is(err, store.ErrNotFound) {
		log.Printf("report_send_now: schedule %s is gone", job.Args.ScheduleID)
		return nil
	}
	if err != nil {
		return err
	}
	res, err := runReport(ctx, w.Store, sched, reports.TriggerManual, reportNow(w.Cfg), time.Time{}, time.Time{}, job.CreatedAt)
	switch {
	case err != nil && !errors.Is(err, store.ErrReportConflict) && isScheduleConfigError(sched):
		// An invalid timezone fails the same way on every attempt.
		return river.JobCancel(fmt.Errorf("schedule %s: %w", sched.ID, err))
	case err != nil:
		return err
	case res.Skipped != "":
		log.Printf("report_send_now: schedule %s: %s", sched.ID, res.Skipped)
	default:
		log.Printf("report_send_now: schedule %s: report %s, %d deliveries", sched.ID, res.ReportID, res.Deliveries)
	}
	return nil
}

// isScheduleConfigError reports whether the schedule's own timing is
// invalid (so retrying can't help).
func isScheduleConfigError(sched store.ReportSchedule) bool {
	_, err := sched.NextRun(time.Now())
	return err != nil
}
