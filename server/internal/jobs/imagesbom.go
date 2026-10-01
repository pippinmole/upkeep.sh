package jobs

// Container image package lists from registry SBOM attestations
// (internal/imagesbom, docs/tasks/phase-2a-image-vulns.md "Worker: image_sbom").
//
//	ingest (InsertTx in the snapshot tx): a host_images range opened with a
//	  repo digest for a key without an ok server list ──> image_sbom{key}   [images]
//	every 10 min (fetching enabled): retry-due rows, keys with a repo
//	  digest but no server row, rows recorded while disabled ─> image_sbom_sweep
//	image_sbom: fetch + parse + WriteImageSBOM ──> match_versions (same tx)
//	  no attestation (scanning on) ──> image_scan{key}                   [image_scan]
//	image_scan: pull + extract + Syft (imagescan) + WriteImageSBOM ──> match_versions
//	image_sbom_sweep also queues image_scan for rows on the scan's work
//	  list (a lost enqueue, rows from before scanning was on)
//
// image_sbom is unique per image key while waiting or running, so a fleet
// reporting the same image enqueues it once. The images queue's worker
// count bounds concurrent registry traffic; the registry client (shared
// by all of them) backs a registry off after a 429. image_scan has its own
// queue (SW_IMAGE_SCAN_WORKERS, default 1): a scan holds disk, CPU and
// memory for minutes, and must not hold up attestation fetches.

import (
	"context"
	"log"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/pippinmole/upkeep.sh/server/internal/imagesbom"
	"github.com/pippinmole/upkeep.sh/server/internal/imagescan"
	"github.com/pippinmole/upkeep.sh/server/internal/registry"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

const (
	QueueImages    = "images"
	QueueImageScan = "image_scan"
)

// Defaults for ImagesConfig.
const (
	DefaultImageWorkers       = 2
	DefaultImageScanWorkers   = 1
	DefaultImageSweepInterval = 10 * time.Minute
	imageSweepBatch           = 500
)

// kindDockerImages is ingest.KindDockerImages (not imported: ingest
// imports jobs).
const kindDockerImages = "images:docker"

// ImagesConfig configures the image_sbom worker.
type ImagesConfig struct {
	// FetchEnabled allows outbound registry fetches (SW_IMAGE_FETCH_ENABLED,
	// on by default in cmd/worker; the zero value is off, so tests never
	// hit the network). When off, image_sbom records
	// store.SBOMReasonFetchDisabled and the sweep isn't scheduled.
	FetchEnabled bool
	// Registry configures the registry client (Guard nil =
	// netguard.FromEnv()).
	Registry registry.Config
	// Workers is the images queue's concurrency (0 = DefaultImageWorkers).
	Workers int
	// SweepInterval is the image_sbom_sweep cadence (0 = default).
	SweepInterval time.Duration
	// Scan enables server-side Syft for images without an attestation
	// (SW_IMAGE_SCAN_ENABLED, on by default in cmd/worker; needs
	// FetchEnabled). Scanner configures it (Registry is set here).
	Scan    bool
	Scanner imagescan.Config
	// ScanWorkers is the image_scan queue's concurrency (0 = default).
	ScanWorkers int
	// DisableSchedule turns the sweep off (tests).
	DisableSchedule bool
	// RetryBase / RetryMax: backoff for failed attempts worth retrying.
	RetryBase, RetryMax time.Duration
}

// ImageSBOMArgs obtains the server's package list for one image key.
type ImageSBOMArgs struct {
	ImageID string `json:"image_id" river:"unique"`
	OS      string `json:"os" river:"unique"`
	Arch    string `json:"arch" river:"unique"`
	Variant string `json:"variant" river:"unique"`
}

func (ImageSBOMArgs) Kind() string { return "image_sbom" }
func (ImageSBOMArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueImages, MaxAttempts: 3, UniqueOpts: uniqueWhileActive}
}

func (a ImageSBOMArgs) key() store.ImageKey {
	return store.ImageKey{ImageID: a.ImageID, OS: a.OS, Arch: a.Arch, Variant: a.Variant}
}

func imageSBOMArgs(k store.ImageKey) ImageSBOMArgs {
	return ImageSBOMArgs{ImageID: k.ImageID, OS: k.OS, Arch: k.Arch, Variant: k.Variant}
}

// ImageScanArgs pulls and scans one image key (server-side Syft).
type ImageScanArgs struct {
	ImageID string `json:"image_id" river:"unique"`
	OS      string `json:"os" river:"unique"`
	Arch    string `json:"arch" river:"unique"`
	Variant string `json:"variant" river:"unique"`
}

func (ImageScanArgs) Kind() string { return "image_scan" }
func (ImageScanArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueImageScan, MaxAttempts: 3, UniqueOpts: uniqueWhileActive}
}

func (a ImageScanArgs) key() store.ImageKey {
	return store.ImageKey{ImageID: a.ImageID, OS: a.OS, Arch: a.Arch, Variant: a.Variant}
}

func imageScanArgs(k store.ImageKey) ImageScanArgs {
	return ImageScanArgs{ImageID: k.ImageID, OS: k.OS, Arch: k.Arch, Variant: k.Variant}
}

// ImageSBOMSweepArgs enqueues image_sbom for the keys store.ImageSBOMSweep
// returns.
type ImageSBOMSweepArgs struct{}

func (ImageSBOMSweepArgs) Kind() string { return "image_sbom_sweep" }
func (ImageSBOMSweepArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueImages, MaxAttempts: 3, UniqueOpts: uniqueWhileActive}
}

// imageSBOMParams returns image_sbom jobs for the image keys a snapshot
// newly reported with a repo digest (store.ImageKeysForSBOMTx), for
// EnqueueAfterIngest. Nothing is queried unless an images range opened.
func imageSBOMParams(ctx context.Context, tx pgx.Tx, hostID string, res store.SnapshotResult) ([]river.InsertManyParams, error) {
	opened := slices.ContainsFunc(res.Facts, func(f store.FactResult) bool {
		return f.Kind == kindDockerImages && f.Opened > 0
	})
	if !opened {
		return nil, nil
	}
	keys, err := store.ImageKeysForSBOMTx(ctx, tx, hostID, res.SnapshotID)
	if err != nil {
		return nil, err
	}
	params := make([]river.InsertManyParams, len(keys))
	for i, k := range keys {
		params[i] = river.InsertManyParams{Args: imageSBOMArgs(k)}
	}
	return params, nil
}

type ImageSBOMWorker struct {
	river.WorkerDefaults[ImageSBOMArgs]
	Store *store.Store
	Cfg   imagesbom.Config
}

// Timeout: a few manifests and one SBOM blob (2 min cap) per repo digest.
func (w *ImageSBOMWorker) Timeout(*river.Job[ImageSBOMArgs]) time.Duration { return 10 * time.Minute }

func (w *ImageSBOMWorker) Work(ctx context.Context, job *river.Job[ImageSBOMArgs]) error {
	f := &imagesbom.Fetcher{
		Store: w.Store, Cfg: w.Cfg,
		AfterWrite: func(ctx context.Context, tx pgx.Tx, res store.ImageSBOMResult) error {
			return EnqueueAfterImageSBOM(ctx, river.ClientFromContext[pgx.Tx](ctx), tx, res)
		},
	}
	start := time.Now()
	out, err := f.Run(ctx, job.Args.key())
	if err != nil {
		return err
	}
	logImageSBOM(out, "image_sbom", time.Since(start))
	if out.Status == store.SBOMStatusOK || out.Status == imagesbom.StatusSkipped {
		return nil
	}
	if out.Scan {
		if _, err := river.ClientFromContext[pgx.Tx](ctx).Insert(ctx, imageScanArgs(out.Key), nil); err != nil {
			return err
		}
	}
	// A host may have reported another repo digest for the key while this
	// ran; its enqueue was dropped as a duplicate of this job, so go again.
	now, err := w.Store.ImageRepoDigests(ctx, job.Args.key())
	if err != nil {
		return err
	}
	if !slices.Equal(now, out.Digests) {
		return river.JobSnooze(time.Second)
	}
	return nil
}

type ImageScanWorker struct {
	river.WorkerDefaults[ImageScanArgs]
	Store *store.Store
	Cfg   imagesbom.Config
}

// Timeout: the scanner's own wall clock plus room for the write.
func (w *ImageScanWorker) Timeout(*river.Job[ImageScanArgs]) time.Duration {
	if w.Cfg.Scanner == nil {
		return time.Minute
	}
	return w.Cfg.Scanner.Timeout() + 5*time.Minute
}

func (w *ImageScanWorker) Work(ctx context.Context, job *river.Job[ImageScanArgs]) error {
	f := &imagesbom.Fetcher{
		Store: w.Store, Cfg: w.Cfg,
		AfterWrite: func(ctx context.Context, tx pgx.Tx, res store.ImageSBOMResult) error {
			return EnqueueAfterImageSBOM(ctx, river.ClientFromContext[pgx.Tx](ctx), tx, res)
		},
	}
	start := time.Now()
	out, err := f.Scan(ctx, job.Args.key())
	if err != nil {
		return err
	}
	logImageSBOM(out, "image_scan", time.Since(start))
	return nil
}

func logImageSBOM(o imagesbom.Outcome, job string, took time.Duration) {
	k := o.Key
	switch o.Status {
	case imagesbom.StatusSkipped:
	case store.SBOMStatusOK:
		log.Printf("%s %s %s/%s%s: %d packages (%d unmapped) from %s via %s, %s %s, os %s %s (release %q) in %.1fs",
			job, k.ImageID, k.OS, k.Arch, variantSuffix(k.Variant), o.Packages, o.Unmapped, o.Ref, o.Via,
			o.ToolName, o.ToolVersion, o.OS.ID, o.OS.VersionID, o.Release, took.Seconds())
	default:
		next := ""
		if o.NextAttemptAt != nil {
			next = ", retry at " + o.NextAttemptAt.UTC().Format(time.RFC3339)
		}
		scan := ""
		if o.Scan {
			scan = ", image_scan queued"
		}
		log.Printf("%s %s %s/%s%s: %s: %s%s%s (%v)", job, k.ImageID, k.OS, k.Arch, variantSuffix(k.Variant),
			o.Status, o.Reason, next, scan, o.Err)
	}
}

func variantSuffix(v string) string {
	if v == "" {
		return ""
	}
	return "/" + v
}

type ImageSBOMSweepWorker struct {
	river.WorkerDefaults[ImageSBOMSweepArgs]
	Store         *store.Store
	RetryDisabled bool // fetching is enabled: retry rows recorded while it wasn't
	Scan          bool // server-side scanning is on: queue its work list too
}

func (w *ImageSBOMSweepWorker) Work(ctx context.Context, _ *river.Job[ImageSBOMSweepArgs]) error {
	keys, err := w.Store.ImageSBOMSweep(ctx, imageSweepBatch, w.RetryDisabled)
	if err != nil {
		return err
	}
	var scanKeys []store.ImageKey
	if w.Scan {
		if scanKeys, err = w.Store.ImageScanSweep(ctx, imageSweepBatch); err != nil {
			return err
		}
	}
	if len(keys)+len(scanKeys) == 0 {
		return nil
	}
	params := make([]river.InsertManyParams, 0, len(keys)+len(scanKeys))
	for _, k := range keys {
		params = append(params, river.InsertManyParams{Args: imageSBOMArgs(k)})
	}
	for _, k := range scanKeys {
		params = append(params, river.InsertManyParams{Args: imageScanArgs(k)})
	}
	if _, err := river.ClientFromContext[pgx.Tx](ctx).InsertMany(ctx, params); err != nil {
		return err
	}
	log.Printf("image_sbom_sweep: %d image keys queued for image_sbom, %d for image_scan", len(keys), len(scanKeys))
	return nil
}

// ImagesFetcherConfig builds the imagesbom configuration (registry client
// and scanner) from cfg; the one-shot commands use it too.
func ImagesFetcherConfig(cfg ImagesConfig) imagesbom.Config {
	icfg := imagesbom.Config{Enabled: cfg.FetchEnabled, RetryBase: cfg.RetryBase, RetryMax: cfg.RetryMax}
	if !cfg.FetchEnabled {
		return icfg
	}
	icfg.Registry = registry.New(cfg.Registry)
	if cfg.Scan {
		scfg := cfg.Scanner
		scfg.Registry = icfg.Registry
		icfg.Scanner = imagescan.New(scfg)
	}
	return icfg
}

// addImageWorkers registers the image workers and returns the images and
// image_scan queues' concurrency and their periodic jobs.
func addImageWorkers(workers *river.Workers, st *store.Store, cfg ImagesConfig) (int, int, []*river.PeriodicJob) {
	icfg := ImagesFetcherConfig(cfg)
	river.AddWorker(workers, &ImageSBOMWorker{Store: st, Cfg: icfg})
	river.AddWorker(workers, &ImageScanWorker{Store: st, Cfg: icfg})
	river.AddWorker(workers, &ImageSBOMSweepWorker{Store: st, RetryDisabled: cfg.FetchEnabled, Scan: icfg.Scanner != nil})

	n := cfg.Workers
	if n <= 0 {
		n = DefaultImageWorkers
	}
	ns := cfg.ScanWorkers
	if ns <= 0 {
		ns = DefaultImageScanWorkers
	}
	if !cfg.FetchEnabled || cfg.DisableSchedule {
		return n, ns, nil
	}
	every := cfg.SweepInterval
	if every <= 0 {
		every = DefaultImageSweepInterval
	}
	return n, ns, []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(every),
			func() (river.JobArgs, *river.InsertOpts) { return ImageSBOMSweepArgs{}, nil },
			&river.PeriodicJobOpts{ID: "image_sbom_sweep", RunOnStart: true}),
	}
}
