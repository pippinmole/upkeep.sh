// Package jobs wires background work onto River (DOMAIN_MODEL.md Q10):
// job argument types, their workers, the periodic schedule, and client
// construction. River's tables come from migrations/0006_river_queue.
//
// Queues:
//   - "feeds":   OSV / KEV / EPSS syncs. Few, long, I/O and CPU heavy.
//   - "matcher": advisory_rematch (and, later, per-version match and
//     findings reconcile jobs).
package jobs

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivertype"

	"github.com/pippinmole/upkeep.sh/server/internal/feeds"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

const (
	QueueFeeds   = "feeds"
	QueueMatcher = "matcher"
)

// uniqueWhileActive: at most one job per kind (and per `river:"unique"`
// args) that is waiting or running. Completed jobs don't block new ones,
// so periodic inserts resume as soon as the previous run finishes, and a
// periodic insert that lands while a sync is still running is dropped
// instead of queueing a second, overlapping sync.
var uniqueWhileActive = river.UniqueOpts{
	ByArgs: true,
	ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRunning,
		rivertype.JobStateRetryable, rivertype.JobStateScheduled,
	},
}

// OSVSyncArgs syncs one OSV ecosystem directory. The sync itself decides
// between incremental and full (see feeds.Syncer.SyncOSV); Full forces a
// full import. Unique per ecosystem regardless of Full, so a full and an
// incremental sync of the same ecosystem never overlap.
type OSVSyncArgs struct {
	Ecosystem string `json:"ecosystem" river:"unique"`
	Full      bool   `json:"full,omitempty"`
}

func (OSVSyncArgs) Kind() string { return "osv_sync" }
func (OSVSyncArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueFeeds, MaxAttempts: 5, UniqueOpts: uniqueWhileActive}
}

type KEVSyncArgs struct{}

func (KEVSyncArgs) Kind() string { return "kev_sync" }
func (KEVSyncArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueFeeds, MaxAttempts: 5, UniqueOpts: uniqueWhileActive}
}

type EPSSSyncArgs struct{}

func (EPSSSyncArgs) Kind() string { return "epss_sync" }
func (EPSSSyncArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueFeeds, MaxAttempts: 5, UniqueOpts: uniqueWhileActive}
}

// AdvisoryRematchArgs is the matcher trigger: enqueued after an advisory
// sync marked (distro, release, source package) keys dirty in
// advisory_changes. It carries no payload: the table is the durable work
// list, so coalescing many syncs into one pending job loses nothing.
type AdvisoryRematchArgs struct{}

func (AdvisoryRematchArgs) Kind() string { return "advisory_rematch" }
func (AdvisoryRematchArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueMatcher, UniqueOpts: uniqueWhileActive}
}

type OSVSyncWorker struct {
	river.WorkerDefaults[OSVSyncArgs]
	Syncer *feeds.Syncer
}

// Timeout: Ubuntu's full import (~800 MB zip, ~7.9 GB of JSON) takes
// minutes; leave ample headroom. Config.RescueStuckJobsAfter is above it.
func (w *OSVSyncWorker) Timeout(*river.Job[OSVSyncArgs]) time.Duration { return time.Hour }

func (w *OSVSyncWorker) Work(ctx context.Context, job *river.Job[OSVSyncArgs]) error {
	st, err := w.Syncer.SyncOSV(ctx, job.Args.Ecosystem, job.Args.Full)
	if err != nil {
		return err
	}
	log.Printf("osv sync %s: %s in %.1fs: %d records, %d relevant, %d written, %d unchanged, %d rows, %d dirty, %d deleted, %d bad",
		st.Ecosystem, st.Mode, st.Seconds, st.Records, st.Relevant, st.Written, st.Unchanged, st.AffectedRows, st.Dirty, st.Deleted, st.BadRecords)
	return nil
}

type KEVSyncWorker struct {
	river.WorkerDefaults[KEVSyncArgs]
	Syncer *feeds.Syncer
}

func (w *KEVSyncWorker) Timeout(*river.Job[KEVSyncArgs]) time.Duration { return 10 * time.Minute }

func (w *KEVSyncWorker) Work(ctx context.Context, _ *river.Job[KEVSyncArgs]) error {
	st, err := w.Syncer.SyncKEV(ctx)
	if err != nil {
		return err
	}
	log.Printf("kev sync: %s %s: %d entries, %d flagged, %d unflagged", st.Mode, st.Catalog, st.Entries, st.Flagged, st.Unflagged)
	return nil
}

type EPSSSyncWorker struct {
	river.WorkerDefaults[EPSSSyncArgs]
	Syncer *feeds.Syncer
}

func (w *EPSSSyncWorker) Timeout(*river.Job[EPSSSyncArgs]) time.Duration { return 10 * time.Minute }

func (w *EPSSSyncWorker) Work(ctx context.Context, _ *river.Job[EPSSSyncArgs]) error {
	st, err := w.Syncer.SyncEPSS(ctx)
	if err != nil {
		return err
	}
	log.Printf("epss sync: %s %s: %d rows, %d updated", st.Mode, st.ScoreDate, st.Rows, st.Updated)
	return nil
}

// AdvisoryRematchWorker is the hook for the matcher (P1b, next task).
type AdvisoryRematchWorker struct {
	river.WorkerDefaults[AdvisoryRematchArgs]
	Store *store.Store
}

func (w *AdvisoryRematchWorker) Work(ctx context.Context, _ *river.Job[AdvisoryRematchArgs]) error {
	// TODO(matcher): drain advisory_changes. For each (distro, release,
	// source_package) row read at time T: evaluate every software_versions
	// row with that (distro, release, source_name) against its
	// advisory_affected rows (server/internal/debversion), rewrite its
	// software_vulnerabilities, reconcile findings for hosts that
	// currently have it, then DELETE the advisory_changes row WHERE
	// changed_at <= T (a newer change re-dirties it and must survive).
	// Until then this is a no-op and the rows stay queued in the table.
	n, err := w.Store.PendingAdvisoryChanges(ctx)
	if err != nil {
		return err
	}
	log.Printf("advisory_rematch: %d (distro, release, source package) keys pending; matcher not implemented yet", n)
	return nil
}

// Config is the worker process's River setup.
type Config struct {
	// PeriodicSyncs registers the scheduled syncs. When false the workers
	// still run (so manually inserted jobs are processed) but nothing is
	// scheduled — for tests and dev stacks that shouldn't hit the network.
	PeriodicSyncs    bool
	OSVEcosystems    []string
	OSVInterval      time.Duration // incremental cadence (full reload cadence is feeds.Config.FullSyncInterval)
	CVEFeedsInterval time.Duration
	FeedWorkers      int // concurrent feed jobs
}

// NewClient builds a River client that works the feeds and matcher queues
// and, if enabled, schedules the periodic syncs. Periodic jobs are only
// enqueued by the elected leader, so running several worker replicas is
// safe; unique opts keep each sync single-flight.
func NewClient(pool *pgxpool.Pool, st *store.Store, syncer *feeds.Syncer, cfg Config) (*river.Client[pgx.Tx], error) {
	workers := river.NewWorkers()
	river.AddWorker(workers, &OSVSyncWorker{Syncer: syncer})
	river.AddWorker(workers, &KEVSyncWorker{Syncer: syncer})
	river.AddWorker(workers, &EPSSSyncWorker{Syncer: syncer})
	river.AddWorker(workers, &AdvisoryRematchWorker{Store: st})

	var periodic []*river.PeriodicJob
	if cfg.PeriodicSyncs {
		for _, eco := range cfg.OSVEcosystems {
			periodic = append(periodic, river.NewPeriodicJob(
				river.PeriodicInterval(cfg.OSVInterval),
				func() (river.JobArgs, *river.InsertOpts) { return OSVSyncArgs{Ecosystem: eco}, nil },
				&river.PeriodicJobOpts{ID: "osv_sync_" + eco, RunOnStart: true},
			))
		}
		periodic = append(periodic,
			river.NewPeriodicJob(river.PeriodicInterval(cfg.CVEFeedsInterval),
				func() (river.JobArgs, *river.InsertOpts) { return KEVSyncArgs{}, nil },
				&river.PeriodicJobOpts{ID: "kev_sync", RunOnStart: true}),
			river.NewPeriodicJob(river.PeriodicInterval(cfg.CVEFeedsInterval),
				func() (river.JobArgs, *river.InsertOpts) { return EPSSSyncArgs{}, nil },
				&river.PeriodicJobOpts{ID: "epss_sync", RunOnStart: true}),
		)
	}

	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues: map[string]river.QueueConfig{
			QueueFeeds:   {MaxWorkers: max(1, cfg.FeedWorkers)},
			QueueMatcher: {MaxWorkers: 1},
		},
		Workers:              workers,
		PeriodicJobs:         periodic,
		RescueStuckJobsAfter: 2 * time.Hour, // > OSVSyncWorker.Timeout
	})
	if err != nil {
		return nil, err
	}

	// Matcher trigger: runs at the end of an OSV sync that changed
	// something. advisory_changes already holds the work durably, so a
	// failed insert here only delays the matcher until the next change.
	syncer.OnAdvisoriesChanged = func(ctx context.Context, feed string, dirty int) error {
		if _, err := client.Insert(ctx, AdvisoryRematchArgs{}, nil); err != nil {
			log.Printf("%s: enqueue advisory_rematch: %v", feed, err)
		}
		return nil
	}
	return client, nil
}
