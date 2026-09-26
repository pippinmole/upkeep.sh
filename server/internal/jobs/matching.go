package jobs

// Matcher and findings jobs (DOMAIN_MODEL.md §2.6).
//
//	ingest (API, InsertTx in the snapshot transaction)
//	  ├─ new / source-reset versions ──> match_versions{ids}      [matcher]
//	  └─ ranges opened/closed, or the
//	     running kernel changed ────────> reconcile_host{host}     [findings]
//	OSV sync marks advisory_changes ────> advisory_rematch          [matcher]
//	worker start + every 5 min ─────────> advisory_rematch, matcher_sweep
//	match_versions / advisory_rematch /
//	  matcher_sweep: versions whose match
//	  set changed ─────────────────────> reconcile_host{host} per host having them
//	KEV / EPSS / OSV sync changed cves ─> findings_rerank{since}   [findings]
//
// Every matcher write is serialized by a Postgres advisory lock (store
// matcherLock), so the matcher queue's concurrency only affects waiting.
// reconcile_host snoozes while the host has versions not yet evaluated,
// so it never resolves findings the pending match job would reopen.

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

const QueueFindings = "findings"

// MatchVersionsArgs evaluates specific software_versions rows (ingest:
// newly interned, or inferred source replaced). Not unique: each carries
// its own ids, and evaluation is idempotent.
type MatchVersionsArgs struct {
	IDs []int64 `json:"ids"`
}

func (MatchVersionsArgs) Kind() string { return "match_versions" }
func (MatchVersionsArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueMatcher, MaxAttempts: 10}
}

// MatcherSweepArgs evaluates every version never evaluated or evaluated by
// an older matcher.Version (initial run, matcher_version bump, safety net).
type MatcherSweepArgs struct{}

func (MatcherSweepArgs) Kind() string { return "matcher_sweep" }
func (MatcherSweepArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueMatcher, UniqueOpts: uniqueWhileActive}
}

// ReconcileHostArgs reconciles one host's vulnerable_package findings.
// Deliberately not unique: River's uniqueness also covers running jobs,
// and a change committed while a reconcile runs must get its own job
// (the running one may have read the inventory before the change).
type ReconcileHostArgs struct {
	HostID string `json:"host_id"`
}

func (ReconcileHostArgs) Kind() string { return "reconcile_host" }
func (ReconcileHostArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueFindings, MaxAttempts: 10}
}

// FindingsRerankArgs recomputes severity of open findings whose CVE
// enrichment changed at or after Since (zero = all open findings).
type FindingsRerankArgs struct {
	Since time.Time `json:"since"`
}

func (FindingsRerankArgs) Kind() string { return "findings_rerank" }
func (FindingsRerankArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueFindings, MaxAttempts: 5}
}

// EnqueueAfterIngest enqueues the matcher/findings work a snapshot push
// implies, inside the snapshot transaction (InsertTx semantics): the jobs
// exist if and only if the snapshot committed.
func EnqueueAfterIngest(ctx context.Context, client *river.Client[pgx.Tx], tx pgx.Tx, hostID string, res store.SnapshotResult) error {
	var params []river.InsertManyParams
	if ids := res.RematchSoftwareIDs(); len(ids) > 0 {
		params = append(params, river.InsertManyParams{Args: MatchVersionsArgs{IDs: ids}})
	}
	if res.InventoryChanged() || res.KernelChanged {
		params = append(params, river.InsertManyParams{Args: ReconcileHostArgs{HostID: hostID}})
	}
	if len(params) == 0 {
		return nil
	}
	_, err := client.InsertManyTx(ctx, tx, params)
	return err
}

// NewInserter returns an insert-only River client (no queues, no workers)
// for the API process: it can InsertTx jobs that the worker process runs.
func NewInserter(pool *pgxpool.Pool) (*river.Client[pgx.Tx], error) {
	return river.NewClient(riverpgxv5.New(pool), &river.Config{})
}

type MatchVersionsWorker struct {
	river.WorkerDefaults[MatchVersionsArgs]
	Store *store.Store
}

func (w *MatchVersionsWorker) Work(ctx context.Context, job *river.Job[MatchVersionsArgs]) error {
	res, err := w.Store.MatchVersions(ctx, job.Args.IDs)
	if err != nil {
		return err
	}
	n, err := reconcileHostsOf(ctx, w.Store, res.Changed)
	if err != nil {
		return err
	}
	if len(res.Changed) > 0 {
		log.Printf("match_versions: %d evaluated, %d changed, %d matches; %d host reconciles queued",
			res.Evaluated, len(res.Changed), res.Matches, n)
	}
	return nil
}

type MatcherSweepWorker struct {
	river.WorkerDefaults[MatcherSweepArgs]
	Store *store.Store
}

func (w *MatcherSweepWorker) Timeout(*river.Job[MatcherSweepArgs]) time.Duration { return time.Hour }

func (w *MatcherSweepWorker) Work(ctx context.Context, _ *river.Job[MatcherSweepArgs]) error {
	res, err := w.Store.SweepStaleVersions(ctx)
	if err != nil {
		return err
	}
	n, err := reconcileHostsOf(ctx, w.Store, res.Changed)
	if err != nil {
		return err
	}
	if res.Evaluated > 0 {
		log.Printf("matcher_sweep: %d versions evaluated in %.2fs, %d changed, %d matches, %d bad versions; %d host reconciles queued",
			res.Evaluated, res.Seconds, len(res.Changed), res.Matches, res.BadVersions, n)
	}
	return nil
}

// AdvisoryRematchWorker drains advisory_changes (store.DrainAdvisoryChanges).
type AdvisoryRematchWorker struct {
	river.WorkerDefaults[AdvisoryRematchArgs]
	Store *store.Store
}

func (w *AdvisoryRematchWorker) Timeout(*river.Job[AdvisoryRematchArgs]) time.Duration {
	return time.Hour
}

func (w *AdvisoryRematchWorker) Work(ctx context.Context, _ *river.Job[AdvisoryRematchArgs]) error {
	res, err := w.Store.DrainAdvisoryChanges(ctx, store.DrainOptions{})
	if err != nil {
		return err
	}
	n, err := reconcileHostsOf(ctx, w.Store, res.Changed)
	if err != nil {
		return err
	}
	if res.Keys > 0 {
		log.Printf("advisory_rematch: %d keys drained in %.2fs (%d with versions, %d re-dirtied and kept); %d versions evaluated, %d changed, %d matches; %d host reconciles queued",
			res.Keys, res.Seconds, res.KeysWithSW, res.Kept, res.Evaluated, len(res.Changed), res.Matches, n)
	}
	return nil
}

type ReconcileHostWorker struct {
	river.WorkerDefaults[ReconcileHostArgs]
	Store *store.Store
}

func (w *ReconcileHostWorker) Work(ctx context.Context, job *river.Job[ReconcileHostArgs]) error {
	res, err := w.Store.ReconcileHostFindings(ctx, job.Args.HostID)
	if errors.Is(err, store.ErrUnevaluated) {
		// The host's match_versions job (inserted in the same transaction
		// as the snapshot) hasn't run yet; matcher_sweep is the backstop.
		return river.JobSnooze(3 * time.Second)
	}
	if err != nil {
		return err
	}
	if res.Opened+res.Reopened+res.Resolved > 0 {
		kernel := res.RunningKernel
		if kernel == "" {
			kernel = "unknown"
		}
		log.Printf("reconcile_host %s: %d opened, %d reopened, %d resolved, %d unchanged (running kernel %s)",
			job.Args.HostID, res.Opened, res.Reopened, res.Resolved, res.Kept, kernel)
	}
	return nil
}

type FindingsRerankWorker struct {
	river.WorkerDefaults[FindingsRerankArgs]
	Store *store.Store
}

func (w *FindingsRerankWorker) Work(ctx context.Context, job *river.Job[FindingsRerankArgs]) error {
	res, err := w.Store.RerankFindings(ctx, job.Args.Since)
	if err != nil {
		return err
	}
	log.Printf("findings_rerank since %s: %d open findings checked, %d re-ranked",
		job.Args.Since.Format(time.RFC3339), res.Checked, res.Updated)
	return nil
}

// reconcileHostsOf queues a reconcile for every host currently carrying
// one of the changed versions.
func reconcileHostsOf(ctx context.Context, st *store.Store, changed []int64) (int, error) {
	hosts, err := st.HostsWithSoftware(ctx, changed)
	if err != nil || len(hosts) == 0 {
		return 0, err
	}
	client := river.ClientFromContext[pgx.Tx](ctx)
	params := make([]river.InsertManyParams, len(hosts))
	for i, h := range hosts {
		params[i] = river.InsertManyParams{Args: ReconcileHostArgs{HostID: h}}
	}
	if _, err := client.InsertMany(ctx, params); err != nil {
		return 0, err
	}
	return len(hosts), nil
}

// enqueueRerank queues a findings re-rank for cves changed since start (a
// minute of slack covers clock skew between this process and Postgres,
// whose now() stamps cves.updated_at).
func enqueueRerank(ctx context.Context, start time.Time) {
	client := river.ClientFromContext[pgx.Tx](ctx)
	if _, err := client.Insert(ctx, FindingsRerankArgs{Since: start.Add(-time.Minute)}, nil); err != nil {
		log.Printf("enqueue findings_rerank: %v", err)
	}
}
