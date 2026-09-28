package jobs

// Container image findings and scores (Phase 2a "Matching", migration
// 0015). Image findings are reconciled by reconcile_host together with the
// host's package findings; these jobs keep image scores current and fan
// image changes out to the hosts running them.
//
//	WriteImageSBOM (image_sbom worker, later the agent path), in its
//	  transaction via EnqueueAfterImageSBOM ─> match_versions{ids}
//	                                        └> reconcile_image{key}      [findings]
//	reconcile_image: score every ok list of the key (snoozes until its
//	  versions are matched) ──> reconcile_host{host} per host having the key
//	match_versions / advisory_rematch / matcher_sweep: versions whose match
//	  set changed ──> image_score{lists holding them}
//	              └─> reconcile_host{host} per host having such an image
//	ingest: a container or image range opened/closed ─> reconcile_host
//	findings_rerank: also re-scores lists matched to changed CVEs
//	worker start + every 5 min ─> image_score_sweep (missing / stale scores)

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

// ReconcileImageArgs is the hook for "an image's package list was written
// or changed": it scores the key's lists and queues reconcile_host for
// every host that has the image. Callers that write a list with
// store.WriteImageSBOM get it through EnqueueAfterImageSBOM; anything else
// that changes which list applies to an image key inserts it directly.
// Not unique, for the same reason as reconcile_host.
type ReconcileImageArgs struct {
	ImageID string `json:"image_id"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Variant string `json:"variant"`
}

func (ReconcileImageArgs) Kind() string { return "reconcile_image" }
func (ReconcileImageArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueFindings, MaxAttempts: 10}
}

// ReconcileImageFor returns the args for an image key.
func ReconcileImageFor(k store.ImageKey) ReconcileImageArgs {
	return ReconcileImageArgs{ImageID: k.ImageID, OS: k.OS, Arch: k.Arch, Variant: k.Variant}
}

func (a ReconcileImageArgs) key() store.ImageKey {
	return store.ImageKey{ImageID: a.ImageID, OS: a.OS, Arch: a.Arch, Variant: a.Variant}
}

// ImageScoreArgs re-scores specific package lists (their versions' matches
// or CVE enrichment changed). Findings are reconciled separately.
type ImageScoreArgs struct {
	SBOMIDs []int64 `json:"sbom_ids"`
}

func (ImageScoreArgs) Kind() string { return "image_score" }
func (ImageScoreArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueFindings, MaxAttempts: 10}
}

// ImageScoreSweepArgs scores every ok list whose score is missing, older
// than the list, or from an older matcher.Version (safety net; coverage
// changes).
type ImageScoreSweepArgs struct{}

func (ImageScoreSweepArgs) Kind() string { return "image_score_sweep" }
func (ImageScoreSweepArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueFindings, UniqueOpts: uniqueWhileActive}
}

// scoreLists scores each list; it reports how many are waiting for the
// matcher.
func scoreLists(ctx context.Context, st *store.Store, ids []int64) (pending int, err error) {
	for _, id := range ids {
		r, err := st.ScoreImageSBOM(ctx, id)
		if err != nil {
			return pending, err
		}
		if r.Pending > 0 {
			pending++
		}
	}
	return pending, nil
}

type ReconcileImageWorker struct {
	river.WorkerDefaults[ReconcileImageArgs]
	Store *store.Store
}

func (w *ReconcileImageWorker) Work(ctx context.Context, job *river.Job[ReconcileImageArgs]) error {
	key := job.Args.key()
	ids, err := w.Store.ImageSBOMIDs(ctx, key)
	if err != nil {
		return err
	}
	pending, err := scoreLists(ctx, w.Store, ids)
	if err != nil {
		return err
	}
	if pending > 0 {
		// The list's match_versions job (inserted with it) hasn't run
		// yet. reconcile_host would snooze on the same versions anyway.
		return river.JobSnooze(3 * time.Second)
	}
	hosts, err := w.Store.HostsWithImage(ctx, key)
	if err != nil {
		return err
	}
	if err := insertReconcileHosts(ctx, hosts); err != nil {
		return err
	}
	log.Printf("reconcile_image %s (%s/%s%s): %d lists scored; %d host reconciles queued",
		key.ImageID, key.OS, key.Arch, key.Variant, len(ids), len(hosts))
	return nil
}

type ImageScoreWorker struct {
	river.WorkerDefaults[ImageScoreArgs]
	Store *store.Store
}

func (w *ImageScoreWorker) Work(ctx context.Context, job *river.Job[ImageScoreArgs]) error {
	pending, err := scoreLists(ctx, w.Store, job.Args.SBOMIDs)
	if err != nil {
		return err
	}
	if pending > 0 {
		return river.JobSnooze(3 * time.Second)
	}
	return nil
}

type ImageScoreSweepWorker struct {
	river.WorkerDefaults[ImageScoreSweepArgs]
	Store *store.Store
}

func (w *ImageScoreSweepWorker) Timeout(*river.Job[ImageScoreSweepArgs]) time.Duration {
	return time.Hour
}

func (w *ImageScoreSweepWorker) Work(ctx context.Context, _ *river.Job[ImageScoreSweepArgs]) error {
	var scored, pending int
	seen := map[int64]bool{}
	for {
		ids, err := w.Store.StaleImageScores(ctx, 500)
		if err != nil {
			return err
		}
		// Lists still waiting for the matcher stay stale; stop once a
		// round brings nothing new.
		var fresh []int64
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				fresh = append(fresh, id)
			}
		}
		if len(fresh) == 0 {
			break
		}
		p, err := scoreLists(ctx, w.Store, fresh)
		if err != nil {
			return err
		}
		scored, pending = scored+len(fresh)-p, pending+p
		if len(ids) < 500 {
			break
		}
	}
	if scored+pending > 0 {
		log.Printf("image_score_sweep: %d lists scored, %d waiting for the matcher", scored, pending)
	}
	return nil
}

// imageWorkOf queues the image side of "these versions' matches changed":
// re-scoring every ok list holding one of them, and reconcile_host for the
// hosts having such an image that aren't in skip (already queued).
func imageWorkOf(ctx context.Context, st *store.Store, changed []int64, skip []string) (int, error) {
	if len(changed) == 0 {
		return 0, nil
	}
	lists, err := st.ImageSBOMsContaining(ctx, changed)
	if err != nil || len(lists) == 0 {
		return 0, err
	}
	ids := make([]int64, len(lists))
	for i, l := range lists {
		ids[i] = l.SBOMID
	}
	client := river.ClientFromContext[pgx.Tx](ctx)
	if _, err := client.Insert(ctx, ImageScoreArgs{SBOMIDs: ids}, nil); err != nil {
		return 0, err
	}
	hosts, err := st.HostsWithImageSoftware(ctx, changed)
	if err != nil {
		return 0, err
	}
	done := make(map[string]bool, len(skip))
	for _, h := range skip {
		done[h] = true
	}
	var todo []string
	for _, h := range hosts {
		if !done[h] {
			todo = append(todo, h)
		}
	}
	return len(todo), insertReconcileHosts(ctx, todo)
}

// rescoreForCVEs re-scores the lists matched to CVEs changed since (the
// findings_rerank counterpart for image scores).
func rescoreForCVEs(ctx context.Context, st *store.Store, since time.Time) (int, error) {
	ids, err := st.ImageSBOMsWithCVEsChangedSince(ctx, since)
	if err != nil {
		return 0, err
	}
	_, err = scoreLists(ctx, st, ids)
	return len(ids), err
}

func insertReconcileHosts(ctx context.Context, hosts []string) error {
	if len(hosts) == 0 {
		return nil
	}
	client := river.ClientFromContext[pgx.Tx](ctx)
	params := make([]river.InsertManyParams, len(hosts))
	for i, h := range hosts {
		params[i] = river.InsertManyParams{Args: ReconcileHostArgs{HostID: h}}
	}
	_, err := client.InsertMany(ctx, params)
	return err
}

// imageWorkers registers this file's workers.
func imageWorkers(workers *river.Workers, st *store.Store) {
	river.AddWorker(workers, &ReconcileImageWorker{Store: st})
	river.AddWorker(workers, &ImageScoreWorker{Store: st})
	river.AddWorker(workers, &ImageScoreSweepWorker{Store: st})
}

// imageScoreSweepJob runs with the matcher safety net.
func imageScoreSweepJob(every time.Duration) *river.PeriodicJob {
	return river.NewPeriodicJob(river.PeriodicInterval(every),
		func() (river.JobArgs, *river.InsertOpts) { return ImageScoreSweepArgs{}, nil },
		&river.PeriodicJobOpts{ID: "image_score_sweep", RunOnStart: true})
}
