package feeds

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/pippinmole/upkeep.sh/server/internal/osv"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

// OSVEcosystems are the OSV bucket directories this product imports. Each
// is a top-level directory (all.zip + modified_id.csv); the per-release
// ones ("Debian:12", "Alpine:v3.20") went stale in 2024-10 and are not
// read. Every directory maps to one distro (osv.DistroFor).
var OSVEcosystems = []string{"Debian", "Ubuntu", "Alpine"}

// OSVStats summarizes one OSV sync (also stored in feed_sync_state.stats).
type OSVStats struct {
	Ecosystem     string  `json:"ecosystem"`
	Mode          string  `json:"mode"` // "full" | "incremental" | "not-modified"
	Reason        string  `json:"reason,omitempty"`
	Records       int     `json:"records"`        // records read (zip entries / changed ids)
	Relevant      int     `json:"relevant"`       // touching a supported release
	Skipped       int     `json:"skipped"`        // already applied (incremental)
	BadRecords    int     `json:"bad_records"`    // failed to parse/normalize; logged and skipped
	Written       int     `json:"written"`        // advisories inserted/updated
	Unchanged     int     `json:"unchanged"`      // same content hash
	AffectedRows  int     `json:"affected_rows"`  // advisory_affected rows written
	Dirty         int     `json:"dirty"`          // (distro, release, source) keys marked (upper bound; per batch)
	Deleted       int     `json:"deleted"`        // advisories removed
	DownloadBytes int64   `json:"download_bytes"` // all.zip size
	Cursor        string  `json:"cursor"`         // newest `modified` applied
	Seconds       float64 `json:"seconds"`
	PeakHeapMB    uint64  `json:"peak_heap_mb"` // runtime HeapSys at the end (approximate peak)
}

// SyncOSV brings one ecosystem directory ("Debian", "Ubuntu", "Alpine") up
// to date.
//
// It runs a full all.zip import when forced, on first run, when the
// supported release set changed since the last full import, or when that
// import is older than Cfg.FullSyncInterval; otherwise it applies the
// records listed in modified_id.csv as newer than the stored cursor,
// escalating to a full import if there are more than
// Cfg.IncrementalMaxChanges of them.
func (s *Syncer) SyncOSV(ctx context.Context, dir string, forceFull bool) (stats OSVStats, err error) {
	feed := osv.SourceFor(dir)
	start := time.Now()
	stats.Ecosystem = dir
	defer func() {
		stats.Seconds = time.Since(start).Round(time.Millisecond).Seconds()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		stats.PeakHeapMB = ms.HeapSys >> 20
		if err != nil {
			_ = s.Store.FeedFailed(context.WithoutCancel(ctx), feed, err)
		}
	}()
	if err := s.Store.FeedAttempt(ctx, feed); err != nil {
		return stats, err
	}
	st, err := s.Store.GetFeedState(ctx, feed)
	if err != nil {
		return stats, err
	}
	releases, err := s.Store.DistroReleases(ctx)
	if err != nil {
		return stats, err
	}
	rels := osv.NewReleases(releases)
	fingerprint := rels.Fingerprint(osv.DistroFor(dir))

	reason := ""
	switch {
	case forceFull:
		reason = "forced"
	case st.Cursor == "" || st.LastFullSyncAt == nil:
		reason = "first sync"
	case st.ConfigHash != fingerprint:
		reason = "supported releases or normalizer changed"
	case time.Since(*st.LastFullSyncAt) >= s.Cfg.FullSyncInterval:
		reason = "periodic full reload"
	}
	if reason == "" {
		var escalate bool
		stats, escalate, err = s.osvIncremental(ctx, dir, feed, st, rels)
		if err != nil || !escalate {
			return stats, err
		}
		reason = fmt.Sprintf("%d changed records > %d", stats.Records, s.Cfg.IncrementalMaxChanges)
		stats = OSVStats{Ecosystem: dir}
	}
	stats.Reason = reason
	return s.osvFull(ctx, dir, feed, rels, fingerprint, stats)
}

// osvIncremental applies records newer than the cursor, per modified_id.csv.
func (s *Syncer) osvIncremental(ctx context.Context, dir, feed string, st store.FeedState, rels osv.Releases) (stats OSVStats, escalate bool, err error) {
	stats = OSVStats{Ecosystem: dir, Mode: "incremental"}
	since, err := time.Parse(time.RFC3339Nano, st.Cursor)
	if err != nil {
		return stats, true, nil // unreadable cursor: rebuild
	}
	client := s.osvClient()
	entries, etag, notModified, err := client.ModifiedSince(ctx, dir, since, st.ETag)
	if err != nil {
		return stats, false, err
	}
	if notModified {
		stats.Mode, stats.Cursor = "not-modified", st.Cursor
		return stats, false, s.Store.FeedSucceeded(ctx, feed, store.FeedSuccess{Stats: stats})
	}
	stats.Records = len(entries)
	if len(entries) > s.Cfg.IncrementalMaxChanges {
		return stats, true, nil
	}
	cursor := st.Cursor
	if len(entries) > 0 {
		cursor = entries[0].Modified.Format(time.RFC3339Nano) // newest first
	}

	// Skip records whose stored modified_at already equals the listed one
	// (e.g. imported by the preceding full sync). Postgres keeps microseconds.
	ids := make([]string, len(entries))
	for i, e := range entries {
		ids[i] = e.ID
	}
	stored, err := s.Store.AdvisoryModifiedAt(ctx, ids)
	if err != nil {
		return stats, false, err
	}
	var todo []string
	for _, e := range entries {
		if t, ok := stored[e.ID]; ok && t.Equal(e.Modified.Truncate(time.Microsecond)) {
			stats.Skipped++
			continue
		}
		todo = append(todo, e.ID)
	}

	var (
		mu         sync.Mutex
		irrelevant []string
	)
	produce := func(ctx context.Context, out chan<- osv.Advisory) error {
		g, ctx := errgroup.WithContext(ctx)
		g.SetLimit(s.Cfg.Workers)
		for _, id := range todo {
			g.Go(func() error {
				b, err := client.Get(ctx, dir, id)
				if errors.Is(err, osv.ErrNotFound) {
					mu.Lock()
					irrelevant = append(irrelevant, id)
					mu.Unlock()
					return nil
				}
				if err != nil {
					return err
				}
				adv, ok, err := parseNormalize(b, feed, rels)
				if err != nil {
					log.Printf("%s: skipping %s: %v", feed, id, err)
					mu.Lock()
					stats.BadRecords++
					mu.Unlock()
					return nil
				}
				if !ok {
					mu.Lock()
					irrelevant = append(irrelevant, id)
					mu.Unlock()
					return nil
				}
				select {
				case out <- adv:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
		}
		return g.Wait()
	}
	w, err := s.pipeline(ctx, produce)
	if err != nil {
		return stats, false, err
	}
	stats.Relevant, stats.Written, stats.Unchanged, stats.AffectedRows, stats.Dirty = w.relevant, w.res.Written, w.res.Unchanged, w.res.Rows, w.res.Dirty
	if stats.Deleted, err = s.Store.DeleteAdvisories(ctx, feed, irrelevant); err != nil {
		return stats, false, err
	}
	stats.Cursor = cursor
	if err := s.Store.FeedSucceeded(ctx, feed, store.FeedSuccess{Cursor: cursor, ETag: etag, Stats: stats}); err != nil {
		return stats, false, err
	}
	return stats, false, s.notifyChanged(ctx, feed, stats.Dirty+stats.Deleted)
}

// osvFull downloads all.zip to a temp file and imports every record,
// then deletes stored advisories of this source that are no longer in it.
func (s *Syncer) osvFull(ctx context.Context, dir, feed string, rels osv.Releases, fingerprint string, stats OSVStats) (OSVStats, error) {
	stats.Mode = "full"
	log.Printf("%s: full sync (%s): downloading all.zip", feed, stats.Reason)
	path, etag, size, err := s.osvClient().DownloadAll(ctx, dir, s.Cfg.TmpDir)
	if err != nil {
		return stats, err
	}
	defer os.Remove(path)
	stats.DownloadBytes = size

	zr, err := zip.OpenReader(path)
	if err != nil {
		return stats, fmt.Errorf("open %s all.zip: %w", dir, err)
	}
	defer zr.Close()
	log.Printf("%s: downloaded %d MB, %d records; importing", feed, size>>20, len(zr.File))

	var (
		mu      sync.Mutex
		keep    []string // relevant ids plus ids that failed to parse (never delete on a parse error)
		newest  time.Time
		records int
	)
	produce := func(ctx context.Context, out chan<- osv.Advisory) error {
		files := make(chan *zip.File)
		g, ctx := errgroup.WithContext(ctx)
		g.Go(func() error {
			defer close(files)
			for _, f := range zr.File {
				select {
				case files <- f:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		})
		for range max(1, s.Cfg.Workers) {
			g.Go(func() error {
				for f := range files {
					b, err := readZipFile(f)
					if err != nil {
						return fmt.Errorf("read %s: %w", f.Name, err)
					}
					rec, perr := osv.Parse(b)
					var (
						adv osv.Advisory
						ok  bool
					)
					if perr == nil {
						adv, ok, perr = osv.Normalize(rec, feed, rels)
					}
					mu.Lock()
					records++
					if perr != nil {
						stats.BadRecords++
						if rec != nil {
							keep = append(keep, rec.ID)
						}
					} else {
						if adv.Modified.After(newest) {
							newest = adv.Modified
						}
						if ok {
							keep = append(keep, adv.ID)
						}
					}
					mu.Unlock()
					if perr != nil {
						log.Printf("%s: skipping %s: %v", feed, f.Name, perr)
						continue
					}
					if !ok {
						continue
					}
					select {
					case out <- adv:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return nil
			})
		}
		return g.Wait()
	}
	w, err := s.pipeline(ctx, produce)
	if err != nil {
		return stats, err
	}
	stats.Records = records
	stats.Relevant, stats.Written, stats.Unchanged, stats.AffectedRows, stats.Dirty = w.relevant, w.res.Written, w.res.Unchanged, w.res.Rows, w.res.Dirty
	if records == 0 {
		return stats, fmt.Errorf("%s all.zip has no records", dir)
	}
	if stats.Deleted, err = s.Store.DeleteAdvisoriesExcept(ctx, feed, keep); err != nil {
		return stats, err
	}
	stats.Cursor = newest.Format(time.RFC3339Nano)
	// The zip's ETag is not modified_id.csv's; clear-by-omission would keep
	// a stale csv ETag, so store a marker that never matches.
	if err := s.Store.FeedSucceeded(ctx, feed, store.FeedSuccess{
		Cursor: stats.Cursor, ETag: "zip:" + etag, ConfigHash: fingerprint, Full: true, Stats: stats,
	}); err != nil {
		return stats, err
	}
	return stats, s.notifyChanged(ctx, feed, stats.Dirty+stats.Deleted)
}

func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func parseNormalize(b []byte, feed string, rels osv.Releases) (osv.Advisory, bool, error) {
	rec, err := osv.Parse(b)
	if err != nil {
		return osv.Advisory{}, false, err
	}
	return osv.Normalize(rec, feed, rels)
}

type pipelineResult struct {
	relevant int
	res      store.AdvisoryWriteResult
}

// pipeline runs produce (which may be concurrent) and a single writer that
// upserts advisories in batches of Cfg.BatchSize (or ~20k affected rows,
// whichever comes first). Memory is bounded by one batch plus the records
// in flight.
func (s *Syncer) pipeline(ctx context.Context, produce func(context.Context, chan<- osv.Advisory) error) (pipelineResult, error) {
	var out pipelineResult
	ch := make(chan osv.Advisory, s.Cfg.Workers*2)
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		defer close(ch)
		return produce(ctx, ch)
	})
	g.Go(func() error {
		var (
			batch []osv.Advisory
			rows  int
		)
		flush := func() error {
			if len(batch) == 0 {
				return nil
			}
			r, err := s.Store.UpsertAdvisories(ctx, batch)
			if err != nil {
				return err
			}
			out.res.Add(r)
			batch, rows = batch[:0], 0
			return nil
		}
		for adv := range ch {
			out.relevant++
			batch = append(batch, adv)
			rows += len(adv.Affected)
			if len(batch) >= s.Cfg.BatchSize || rows >= 20000 {
				if err := flush(); err != nil {
					return err
				}
			}
		}
		return flush()
	})
	return out, g.Wait()
}

func (s *Syncer) notifyChanged(ctx context.Context, feed string, n int) error {
	if n == 0 || s.OnAdvisoriesChanged == nil {
		return nil
	}
	return s.OnAdvisoriesChanged(ctx, feed, n)
}
