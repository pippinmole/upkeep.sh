package jobs

// Alerting jobs (docs/ARCHITECTURE.md "Alerting"), queue "alerts":
//
//	reconcile_host (findings tx) ──┐ alert_events rows + alert_evaluate (InsertTx)
//	agent_health (every 1m) ───────┘
//	alert_evaluate    drain the outbox: match rules, dedup, immediate
//	                  notifications or digest items; alert_deliver per delivery (InsertTx)
//	alert_digest      (every 1m) flush digest rules whose interval elapsed
//	alert_deliver     send one delivery through its channel type's Notifier;
//	                  retried with backoff (deliverBackoff) on retryable errors
//	alert_prune       (hourly) retention for events, the delivery log and reports
//
// alert_evaluate also runs every minute as a safety net. None of this runs
// in the API: ingest never waits on alerting.

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/pippinmole/upkeep.sh/server/internal/notify"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

const QueueAlerts = "alerts"

// AlertEvaluateArgs drains alert_events. Not unique: River uniqueness also
// covers running jobs, and events committed while one runs need another
// pass; evaluation is serialized by an advisory lock and a pass with
// nothing to do is one cheap query.
type AlertEvaluateArgs struct{}

func (AlertEvaluateArgs) Kind() string { return "alert_evaluate" }
func (AlertEvaluateArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueAlerts, MaxAttempts: 5}
}

type AlertDigestArgs struct{}

func (AlertDigestArgs) Kind() string { return "alert_digest" }
func (AlertDigestArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueAlerts, MaxAttempts: 3, UniqueOpts: uniqueWhileActive}
}

type AgentHealthArgs struct{}

func (AgentHealthArgs) Kind() string { return "agent_health" }
func (AgentHealthArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueAlerts, MaxAttempts: 3, UniqueOpts: uniqueWhileActive}
}

type AlertPruneArgs struct{}

func (AlertPruneArgs) Kind() string { return "alert_prune" }
func (AlertPruneArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueAlerts, MaxAttempts: 3, UniqueOpts: uniqueWhileActive}
}

// AlertDeliverArgs sends one notification_deliveries row. The dashboard's
// "send test" inserts this job with plain SQL (web/src/lib/river.ts), so
// keep the kind and args shape stable.
type AlertDeliverArgs struct {
	DeliveryID string `json:"delivery_id"`
}

// DeliverMaxAttempts: with deliverBackoff, retries span about 11 hours.
const DeliverMaxAttempts = 8

func (AlertDeliverArgs) Kind() string { return "alert_deliver" }
func (AlertDeliverArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueAlerts, MaxAttempts: DeliverMaxAttempts}
}

// deliverBackoff is the wait after failed attempt N (1-based).
var deliverBackoff = []time.Duration{
	30 * time.Second, 2 * time.Minute, 10 * time.Minute, 30 * time.Minute,
	time.Hour, 3 * time.Hour, 6 * time.Hour,
}

// NextDeliverRetry is the retry delay after failed attempt n (1-based).
func NextDeliverRetry(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	return deliverBackoff[min(n, len(deliverBackoff))-1]
}

// AlertingConfig is what the alerting workers need.
type AlertingConfig struct {
	Notifiers    *notify.Registry
	DashboardURL string
	// Now is the clock (tests); nil = time.Now.
	Now func() time.Time
}

func (c AlertingConfig) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

// enqueueDeliveries is store.EnqueueDeliveries on the job's River client.
func enqueueDeliveries(ctx context.Context, tx pgx.Tx, ids []string) error {
	client := river.ClientFromContext[pgx.Tx](ctx)
	params := make([]river.InsertManyParams, len(ids))
	for i, id := range ids {
		params[i] = river.InsertManyParams{Args: AlertDeliverArgs{DeliveryID: id}}
	}
	_, err := client.InsertManyTx(ctx, tx, params)
	return err
}

// EnqueueAlertEvaluate is the reconcile hook: when the reconcile wrote
// alert events, queue an evaluation in the same transaction.
func EnqueueAlertEvaluate(ctx context.Context, tx pgx.Tx, res store.ReconcileResult) error {
	if res.AlertEvents == 0 {
		return nil
	}
	_, err := river.ClientFromContext[pgx.Tx](ctx).InsertTx(ctx, tx, AlertEvaluateArgs{}, nil)
	return err
}

type AlertEvaluateWorker struct {
	river.WorkerDefaults[AlertEvaluateArgs]
	Store *store.Store
	Cfg   AlertingConfig
}

func (w *AlertEvaluateWorker) Work(ctx context.Context, _ *river.Job[AlertEvaluateArgs]) error {
	res, err := w.Store.EvaluateAlerts(ctx, w.Cfg.now(), store.AlertOptions{
		DashboardURL: w.Cfg.DashboardURL, Enqueue: enqueueDeliveries,
	})
	if err != nil {
		return err
	}
	if res.Events > 0 {
		log.Printf("alert_evaluate: %d events, %d matches, %d suppressed (dedup), %d to digests, %d notifications, %d deliveries",
			res.Events, res.Matched, res.Suppressed, res.Digested, res.Notifications, res.Deliveries)
	}
	return nil
}

type AlertDigestWorker struct {
	river.WorkerDefaults[AlertDigestArgs]
	Store *store.Store
	Cfg   AlertingConfig
}

func (w *AlertDigestWorker) Work(ctx context.Context, _ *river.Job[AlertDigestArgs]) error {
	res, err := w.Store.FlushDigests(ctx, w.Cfg.now(), store.AlertOptions{
		DashboardURL: w.Cfg.DashboardURL, Enqueue: enqueueDeliveries,
	})
	if err != nil {
		return err
	}
	if res.Rules > 0 {
		log.Printf("alert_digest: %d rules, %d events, %d notifications, %d deliveries",
			res.Rules, res.Events, res.Notifications, res.Deliveries)
	}
	return nil
}

type AgentHealthWorker struct {
	river.WorkerDefaults[AgentHealthArgs]
	Store *store.Store
	Cfg   AlertingConfig
}

func (w *AgentHealthWorker) Work(ctx context.Context, _ *river.Job[AgentHealthArgs]) error {
	res, err := w.Store.CheckAgentHealth(ctx, w.Cfg.now())
	if err != nil {
		return err
	}
	if res.Events > 0 {
		log.Printf("agent_health: %d agents changed state, %d alert events", res.Changed, res.Events)
		if _, err := river.ClientFromContext[pgx.Tx](ctx).Insert(ctx, AlertEvaluateArgs{}, nil); err != nil {
			log.Printf("enqueue alert_evaluate: %v", err) // the periodic evaluate picks it up
		}
	}
	return nil
}

type AlertPruneWorker struct {
	river.WorkerDefaults[AlertPruneArgs]
	Store *store.Store
	Cfg   AlertingConfig
}

func (w *AlertPruneWorker) Work(ctx context.Context, _ *river.Job[AlertPruneArgs]) error {
	res, err := w.Store.PruneAlerting(ctx, w.Cfg.now(), 30*24*time.Hour, 90*24*time.Hour, 365*24*time.Hour)
	if err != nil {
		return err
	}
	if res.Events+res.Notifications+res.Dedup+res.Reports > 0 {
		log.Printf("alert_prune: %d events, %d notifications, %d dedup marks, %d reports",
			res.Events, res.Notifications, res.Dedup, res.Reports)
	}
	return nil
}

type AlertDeliverWorker struct {
	river.WorkerDefaults[AlertDeliverArgs]
	Store *store.Store
	Cfg   AlertingConfig
}

func (w *AlertDeliverWorker) Timeout(*river.Job[AlertDeliverArgs]) time.Duration { return time.Minute }

func (w *AlertDeliverWorker) NextRetry(job *river.Job[AlertDeliverArgs]) time.Time {
	return time.Now().Add(NextDeliverRetry(job.Attempt))
}

func (w *AlertDeliverWorker) Work(ctx context.Context, job *river.Job[AlertDeliverArgs]) error {
	d, err := w.Store.LoadDelivery(ctx, job.Args.DeliveryID)
	if errors.Is(err, store.ErrNotFound) {
		return nil // pruned or its user deleted
	}
	if err != nil {
		return err
	}
	if d.Status == store.DeliveryDelivered || d.Status == store.DeliveryFailed {
		return nil // already final (duplicate job)
	}
	fail := func(msg string) error {
		_, err := w.Store.RecordAttempt(ctx, d.ID, store.Attempt{Error: msg, Status: store.DeliveryFailed}, w.Cfg.now())
		return err
	}
	switch {
	case d.ReportDeleted:
		return fail("report was deleted (its schedule was deleted)")
	case d.ChannelID == nil:
		return fail("channel was deleted")
	case !d.ChannelEnabled && d.Kind != notify.KindTest:
		return fail("channel is disabled")
	}
	n, ok := w.Cfg.Notifiers.Get(d.ChannelType)
	if !ok {
		return fail("unknown channel type " + d.ChannelType)
	}
	if r := d.Notification.Report; r != nil {
		// Built at send time: the snapshot has no URLs (the dashboard's base
		// URL can change after a report is stored).
		r.URL = store.ReportURL(w.Cfg.DashboardURL, r.ID)
	}

	start := time.Now()
	res, sendErr := n.Send(ctx, d.Config, d.Notification)
	a := store.Attempt{StatusCode: res.StatusCode, Duration: time.Since(start)}
	final := job.Attempt >= job.MaxAttempts
	switch {
	case sendErr == nil:
		a.Status = store.DeliveryDelivered
	case notify.IsPermanent(sendErr) || final:
		a.Status = store.DeliveryFailed
	default:
		a.Status = store.DeliveryRetrying
	}
	if sendErr != nil {
		a.Error = sendErr.Error()
		if res.Response != "" {
			a.Error += ": " + res.Response
		}
	}
	if _, err := w.Store.RecordAttempt(ctx, d.ID, a, w.Cfg.now()); err != nil {
		return err
	}
	if a.Status == store.DeliveryRetrying {
		return sendErr // River retries at NextRetry
	}
	return nil
}
