package jobs

// Report job integration tests against a real, fully migrated Postgres;
// skipped unless SW_TEST_DATABASE_URL is set. report_due is global (every
// user's due schedules), so like the alerting tests these start a River
// client that works every queued job: use a database of your own, or stop
// any other worker on it while they run.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/pippinmole/upkeep.sh/server/internal/feeds"
	"github.com/pippinmole/upkeep.sh/server/internal/notify"
	"github.com/pippinmole/upkeep.sh/server/internal/reports"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

// schedule inserts a weekly Monday 07:00 London report schedule for the
// fixture's user, sending to channels.
func (f *alertFixture) schedule(name, tz string, nextRunAt *time.Time, channels ...string) string {
	f.t.Helper()
	var id string
	if err := f.s.Pool.QueryRow(context.Background(), `
		INSERT INTO report_schedules (user_id, name, cadence, weekday, hour, timezone, next_run_at)
		VALUES ($1, $2, 'weekly', 1, 7, $3, $4) RETURNING id
	`, f.userID, name, tz, nextRunAt).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	for _, c := range channels {
		f.exec(`INSERT INTO report_schedule_channels (schedule_id, channel_id, user_id) VALUES ($1, $2, $3)`, id, c, f.userID)
	}
	return id
}

type reportRow struct {
	id, trigger             string
	prev                    *string
	generatedAt, start, end time.Time
	ranking                 int
}

// reports lists a schedule's reports, oldest first.
func (f *alertFixture) reports(scheduleID string) []reportRow {
	f.t.Helper()
	rows, err := f.s.Pool.Query(context.Background(), `
		SELECT id::text, trigger, previous_report_id::text, generated_at, period_start, period_end, ranking_version
		FROM reports WHERE schedule_id = $1 ORDER BY generated_at, id
	`, scheduleID)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []reportRow
	for rows.Next() {
		var r reportRow
		if err := rows.Scan(&r.id, &r.trigger, &r.prev, &r.generatedAt, &r.start, &r.end, &r.ranking); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func (f *alertFixture) runTimes(scheduleID string) (next, last *time.Time) {
	f.t.Helper()
	if err := f.s.Pool.QueryRow(context.Background(), `SELECT next_run_at, last_run_at FROM report_schedules WHERE id = $1`,
		scheduleID).Scan(&next, &last); err != nil {
		f.t.Fatal(err)
	}
	return next, last
}

func TestReportJobs(t *testing.T) {
	f := newAlertFixture(t)
	ctx := context.Background()
	fake := &fakeNotifier{}
	room := f.channel("fake room", "fake", map[string]string{"room": "#reports"}, map[string]string{"token": "t0k"})
	off := f.channel("disabled room", "fake", map[string]string{"room": "#off"}, nil)
	f.exec(`UPDATE notification_channels SET enabled = false WHERE id = $1`, off)

	client, err := NewClient(f.s.Pool, f.s, &feeds.Syncer{Store: f.s, Cfg: feeds.DefaultConfig()}, Config{
		DisableMatcherSchedule: true, DisableAlertSchedule: true,
		Alerting: AlertingConfig{Notifiers: notify.NewRegistry(fake), DashboardURL: "https://upkeep.example/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(ctx); err != nil {
		t.Fatal(err)
	}
	var jobIDs []int64
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = client.Stop(stopCtx)
		_, _ = f.s.Pool.Exec(context.Background(), `
			DELETE FROM river_job WHERE id = ANY ($1) OR (kind = 'alert_deliver' AND args->>'delivery_id' IN (
				SELECT id::text FROM notification_deliveries WHERE user_id = $2))
		`, jobIDs, f.userID)
	})

	// run inserts a job and waits for River to finish it.
	run := func(args river.JobArgs) {
		t.Helper()
		res, err := client.Insert(ctx, args, nil)
		if err != nil {
			t.Fatal(err)
		}
		jobIDs = append(jobIDs, res.Job.ID)
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			var state string
			if err := f.s.Pool.QueryRow(ctx, `SELECT state FROM river_job WHERE id = $1`, res.Job.ID).Scan(&state); err != nil {
				t.Fatal(err)
			}
			switch rivertype.JobState(state) {
			case rivertype.JobStateCompleted:
				return
			case rivertype.JobStateDiscarded, rivertype.JobStateCancelled, rivertype.JobStateRetryable:
				t.Fatalf("%s job %d: %s", args.Kind(), res.Job.ID, state)
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("%s job %d did not complete", args.Kind(), res.Job.ID)
	}
	awaitFake := func(n int) []notify.Notification {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for len(fake.all()) < n && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		got := fake.all()
		if len(got) != n {
			t.Fatalf("fake channel got %d notifications, want %d", len(got), n)
		}
		return got
	}

	// 1. A run missed for weeks (worker down): runs once, and the next run
	// is in the future, not the missed occurrences one by one.
	missed := time.Now().Add(-21 * 24 * time.Hour)
	weekly := f.schedule("Monday patch list", "Europe/London", &missed, room, off)
	before := time.Now()
	run(ReportDueArgs{})
	rs := f.reports(weekly)
	if len(rs) != 1 {
		t.Fatalf("after a missed run: %d reports, want 1", len(rs))
	}
	first := rs[0]
	wantPeriod, _ := reports.PeriodFor(reports.CadenceWeekly, "Europe/London", nil, first.generatedAt)
	if first.trigger != reports.TriggerScheduled || first.prev != nil || first.ranking != reports.RankingVersion ||
		!first.end.Equal(first.generatedAt) || !first.start.Equal(wantPeriod.Start) || first.generatedAt.Before(before.Add(-time.Second)) {
		t.Fatalf("first report: %+v (want period start %s)", first, wantPeriod.Start)
	}
	next, last := f.runTimes(weekly)
	if next == nil || !next.After(time.Now()) || next.Sub(time.Now()) > 7*24*time.Hour || last == nil || !last.Equal(first.generatedAt) {
		t.Fatalf("after run: next %v, last %v", next, last)
	}
	if l := next.In(mustLoc(t, "Europe/London")); l.Weekday() != time.Monday || l.Hour() != 7 {
		t.Fatalf("next run %s is not Monday 07:00 London", l)
	}
	// One notification pointing at the report, one delivery (the disabled
	// channel gets none), delivered through the fake channel type with the
	// stored snapshot and the report link.
	var nid, kind, summary string
	if err := f.s.Pool.QueryRow(ctx, `SELECT id::text, kind, summary FROM notifications WHERE report_id = $1`, first.id).
		Scan(&nid, &kind, &summary); err != nil {
		t.Fatal(err)
	}
	if kind != notify.KindReport || summary != "Monday patch list: all clear" {
		t.Fatalf("notification %s / %q", kind, summary)
	}
	if n := f.count(`SELECT count(*) FROM notification_deliveries WHERE notification_id = $1`, nid); n != 1 {
		t.Fatalf("deliveries = %d, want 1", n)
	}
	got := awaitFake(1)[0]
	if got.Kind != notify.KindReport || got.ID != nid || got.Report == nil || got.Report.ID != first.id ||
		got.Report.URL != "https://upkeep.example/dashboard/reports/"+first.id || got.Report.Snapshot == nil ||
		got.Report.Snapshot.Schedule.ID != weekly || got.Report.Snapshot.Estate.Hosts != 1 ||
		got.Report.Snapshot.Changes != nil || got.Summary != summary || got.Events == nil || got.Rule != nil {
		t.Fatalf("delivered notification: %+v / %+v", got, got.Report)
	}
	if !got.Report.Snapshot.GeneratedAt.Equal(first.generatedAt) {
		t.Fatalf("snapshot generated_at %s, row %s", got.Report.Snapshot.GeneratedAt, first.generatedAt)
	}

	// 2. Nothing due: nothing runs.
	run(ReportDueArgs{})
	if n := len(f.reports(weekly)); n != 1 {
		t.Fatalf("second pass ran again: %d reports", n)
	}

	// 3. Due again: the second report compares with the first.
	f.exec(`UPDATE report_schedules SET next_run_at = now() - interval '1 minute' WHERE id = $1`, weekly)
	run(ReportDueArgs{})
	rs = f.reports(weekly)
	if len(rs) != 2 || rs[1].prev == nil || *rs[1].prev != first.id || !rs[1].start.Equal(first.generatedAt) {
		t.Fatalf("second report: %+v", rs)
	}
	second := rs[1]
	got = awaitFake(2)[1]
	if c := got.Report.Snapshot.Changes; c == nil || c.PreviousReportID != first.id || !c.Comparable ||
		c.Metrics["total_open_findings"].Delta != 0 {
		t.Fatalf("second report changes: %+v", c)
	}

	// 4. A new schedule (next_run_at NULL) gets its next run computed and
	// doesn't run; one with a timezone the worker doesn't know is left
	// alone and doesn't fail the pass.
	fresh := f.schedule("Fresh", "America/New_York", nil, room)
	bad := f.schedule("Bad zone", "Mars/Olympus_Mons", nil, room)
	run(ReportDueArgs{})
	if next, _ := f.runTimes(fresh); next == nil || !next.After(time.Now()) || len(f.reports(fresh)) != 0 {
		t.Fatalf("fresh schedule: next %v, %d reports", next, len(f.reports(fresh)))
	}
	if next, _ := f.runTimes(bad); next != nil || len(f.reports(bad)) != 0 {
		t.Fatalf("bad timezone schedule: next %v", next)
	}

	// 5. Send now, on a disabled schedule: a manual report compared with
	// the previous one; next_run_at untouched.
	f.exec(`UPDATE report_schedules SET enabled = false WHERE id = $1`, weekly)
	nextBefore, _ := f.runTimes(weekly)
	run(ReportSendNowArgs{ScheduleID: weekly})
	rs = f.reports(weekly)
	if len(rs) != 3 || rs[2].trigger != reports.TriggerManual || rs[2].prev == nil || *rs[2].prev != second.id {
		t.Fatalf("manual report: %+v", rs)
	}
	nextAfter, lastAfter := f.runTimes(weekly)
	if nextAfter == nil || !nextAfter.Equal(*nextBefore) || lastAfter == nil || !lastAfter.Equal(rs[2].generatedAt) {
		t.Fatalf("send now moved next_run_at %v -> %v (last %v)", nextBefore, nextAfter, lastAfter)
	}
	if got := awaitFake(3)[2]; got.Report.Snapshot.Trigger != reports.TriggerManual {
		t.Fatalf("manual snapshot trigger %q", got.Report.Snapshot.Trigger)
	}
	// Send now for a schedule that's gone: nothing to do, not an error.
	run(ReportSendNowArgs{ScheduleID: "00000000-0000-0000-0000-000000000000"})

	// 6. Double-run guards, at the store level.
	sched, err := f.s.LoadReportSchedule(ctx, weekly)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	snap := reports.Snapshot{Schedule: sched.Ref(), Period: reports.Period{Start: now, End: now}, RankingVersion: reports.RankingVersion}
	prevID := rs[2].id
	f.exec(`UPDATE report_schedules SET enabled = true WHERE id = $1`, weekly)
	// A pass that saw an older next_run_at (another pass ran it first).
	res, err := f.s.StoreReport(ctx, store.NewReport{Schedule: sched, Trigger: reports.TriggerScheduled, Snapshot: snap,
		PreviousID: &prevID, Now: now, ExpectNextRunAt: missed, NextRunAt: now.Add(time.Hour)}, nil)
	if err != nil || res.Skipped == "" {
		t.Fatalf("stale scheduled run: %+v, %v", res, err)
	}
	// A retried send-now job whose report was already stored.
	res, err = f.s.StoreReport(ctx, store.NewReport{Schedule: sched, Trigger: reports.TriggerManual, Snapshot: snap,
		PreviousID: &prevID, Now: now, ManualSince: rs[2].generatedAt.Add(-time.Second)}, nil)
	if err != nil || res.Skipped != "already sent" {
		t.Fatalf("retried send now: %+v, %v", res, err)
	}
	// Built against a previous report that is no longer the latest.
	if _, err := f.s.StoreReport(ctx, store.NewReport{Schedule: sched, Trigger: reports.TriggerManual, Snapshot: snap,
		PreviousID: &first.id, Now: now}, nil); !errors.Is(err, store.ErrReportConflict) {
		t.Fatalf("stale previous report: %v", err)
	}
	if n := len(f.reports(weekly)); n != 3 {
		t.Fatalf("guards stored reports: %d", n)
	}

	// 7. A report deleted with its schedule before delivery: the pending
	// delivery fails permanently.
	doomed := f.schedule("Doomed", "UTC", nil, room)
	dsched, err := f.s.LoadReportSchedule(ctx, doomed)
	if err != nil {
		t.Fatal(err)
	}
	dsnap := reports.Snapshot{Schedule: dsched.Ref(), Period: reports.Period{Start: now, End: now}, RankingVersion: reports.RankingVersion}
	stored, err := f.s.StoreReport(ctx, store.NewReport{Schedule: dsched, Trigger: reports.TriggerManual, Snapshot: dsnap, Now: now}, nil)
	if err != nil || stored.Deliveries != 1 {
		t.Fatalf("store: %+v, %v", stored, err)
	}
	var did string
	if err := f.s.Pool.QueryRow(ctx, `SELECT id::text FROM notification_deliveries WHERE notification_id = $1`, stored.NotificationID).Scan(&did); err != nil {
		t.Fatal(err)
	}
	f.exec(`DELETE FROM report_schedules WHERE id = $1`, doomed)
	w := &AlertDeliverWorker{Store: f.s, Cfg: AlertingConfig{Notifiers: notify.NewRegistry(fake)}}
	if err := w.Work(ctx, &river.Job[AlertDeliverArgs]{JobRow: &rivertype.JobRow{Attempt: 1, MaxAttempts: DeliverMaxAttempts},
		Args: AlertDeliverArgs{DeliveryID: did}}); err != nil {
		t.Fatal(err)
	}
	var status, lastErr string
	if err := f.s.Pool.QueryRow(ctx, `SELECT status, last_error FROM notification_deliveries WHERE id = $1`, did).Scan(&status, &lastErr); err != nil {
		t.Fatal(err)
	}
	if status != store.DeliveryFailed || lastErr != "report was deleted (its schedule was deleted)" || len(fake.all()) != 3 {
		t.Fatalf("deleted report delivery: %s / %s (%d sent)", status, lastErr, len(fake.all()))
	}
}

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}
