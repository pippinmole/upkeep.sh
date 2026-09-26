package feeds

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/cvefeeds"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

const (
	FeedKEV  = "cisa-kev"
	FeedEPSS = "first-epss"
)

type KEVStats struct {
	Mode      string  `json:"mode"` // "applied" | "not-modified"
	Source    string  `json:"source"`
	Catalog   string  `json:"catalog_version,omitempty"`
	Entries   int     `json:"entries"`
	Flagged   int     `json:"flagged"`   // rows inserted or changed
	Unflagged int     `json:"unflagged"` // CVEs removed from the catalog
	Seconds   float64 `json:"seconds"`
}

// SyncKEV applies the CISA KEV catalog to cves (conditional GET on ETag).
func (s *Syncer) SyncKEV(ctx context.Context) (stats KEVStats, err error) {
	start := time.Now()
	defer func() {
		stats.Seconds = time.Since(start).Round(time.Millisecond).Seconds()
		if err != nil {
			_ = s.Store.FeedFailed(context.WithoutCancel(ctx), FeedKEV, err)
		}
	}()
	if err := s.Store.FeedAttempt(ctx, FeedKEV); err != nil {
		return stats, err
	}
	st, err := s.Store.GetFeedState(ctx, FeedKEV)
	if err != nil {
		return stats, err
	}
	// The stored ETag is "<url> <etag>": only sent back to the URL that issued it.
	etagURL, etag, _ := strings.Cut(st.ETag, " ")
	var (
		resp    *http.Response
		srcURL  string
		lastErr error
	)
	for _, u := range s.Cfg.KEVURLs {
		cond := ""
		if u == etagURL {
			cond = etag
		}
		resp, lastErr = s.fetch(ctx, u, cond)
		if lastErr == nil {
			srcURL = u
			break
		}
		log.Printf("%s: %v", FeedKEV, lastErr)
	}
	if resp == nil {
		if lastErr == nil {
			lastErr = errors.New("no KEV URLs configured")
		}
		return stats, lastErr
	}
	defer resp.Body.Close()
	stats.Source = srcURL
	if resp.StatusCode == http.StatusNotModified {
		stats.Mode = "not-modified"
		return stats, s.Store.FeedSucceeded(ctx, FeedKEV, store.FeedSuccess{Stats: stats})
	}
	cat, err := cvefeeds.ParseKEV(resp.Body)
	if err != nil {
		return stats, err
	}
	stats.Mode, stats.Catalog, stats.Entries = "applied", cat.Version, len(cat.Entries)
	if stats.Flagged, stats.Unflagged, err = s.Store.ApplyKEV(ctx, cat); err != nil {
		return stats, err
	}
	return stats, s.Store.FeedSucceeded(ctx, FeedKEV, store.FeedSuccess{
		Cursor: cat.Version, ETag: kevETag(srcURL, resp.Header.Get("ETag")), Stats: stats,
	})
}

func kevETag(url, etag string) string {
	if etag == "" {
		return url + " -" // never matches a real ETag; still replaces a stale one
	}
	return url + " " + etag
}

type EPSSStats struct {
	Mode      string  `json:"mode"` // "applied" | "same-date"
	ScoreDate string  `json:"score_date"`
	Model     string  `json:"model_version"`
	Rows      int     `json:"rows"`
	Updated   int     `json:"updated"` // rows inserted or with changed values
	Seconds   float64 `json:"seconds"`
}

// SyncEPSS streams the current EPSS CSV (gzip) into cves. A feed whose
// score date equals the stored cursor is skipped after reading its header.
func (s *Syncer) SyncEPSS(ctx context.Context) (stats EPSSStats, err error) {
	start := time.Now()
	defer func() {
		stats.Seconds = time.Since(start).Round(time.Millisecond).Seconds()
		if err != nil {
			_ = s.Store.FeedFailed(context.WithoutCancel(ctx), FeedEPSS, err)
		}
	}()
	if err := s.Store.FeedAttempt(ctx, FeedEPSS); err != nil {
		return stats, err
	}
	st, err := s.Store.GetFeedState(ctx, FeedEPSS)
	if err != nil {
		return stats, err
	}
	resp, err := s.fetch(ctx, s.Cfg.EPSSURL, "")
	if err != nil {
		return stats, err
	}
	defer resp.Body.Close()
	r, err := cvefeeds.NewEPSSReader(resp.Body)
	if err != nil {
		return stats, err
	}
	defer r.Close()
	stats.ScoreDate = r.Header.ScoreDate.Format(time.DateOnly)
	stats.Model = r.Header.ModelVersion
	if stats.ScoreDate == st.Cursor {
		stats.Mode = "same-date"
		return stats, s.Store.FeedSucceeded(ctx, FeedEPSS, store.FeedSuccess{Stats: stats})
	}
	stats.Mode = "applied"
	if stats.Rows, stats.Updated, err = s.Store.ApplyEPSS(ctx, r); err != nil {
		return stats, err
	}
	return stats, s.Store.FeedSucceeded(ctx, FeedEPSS, store.FeedSuccess{Cursor: stats.ScoreDate, Stats: stats})
}

// fetch GETs url (following redirects), optionally conditional on etag.
// The caller closes the body; statuses other than 200/304 are errors.
func (s *Syncer) fetch(ctx context.Context, url, etag string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotModified {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return resp, nil
}
