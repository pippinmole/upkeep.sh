// Package feeds runs the advisory and enrichment syncs: OSV Debian/Ubuntu
// into advisories/advisory_affected, and CISA KEV + FIRST EPSS into cves.
// Each sync is a plain function call; server/internal/jobs schedules them
// on River, and `worker sync ...` runs them directly.
package feeds

import (
	"context"
	"net/http"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/cvefeeds"
	"github.com/pippinmole/upkeep.sh/server/internal/osv"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

type Config struct {
	OSVBaseURL string
	// KEVURLs are tried in order until one answers 200/304.
	KEVURLs []string
	EPSSURL string
	// TmpDir holds the downloaded all.zip during a full OSV sync (Ubuntu's
	// is ~800 MB). Empty = os.TempDir().
	TmpDir string
	// FullSyncInterval: an OSV sync becomes a full all.zip import when the
	// last full one is older than this (self-healing weekly reload).
	FullSyncInterval time.Duration
	// IncrementalMaxChanges: an incremental sync with more changed records
	// than this runs as a full import instead.
	IncrementalMaxChanges int
	// Workers parse/fetch records in parallel; one writer batches them.
	Workers   int
	BatchSize int
}

func DefaultConfig() Config {
	return Config{
		OSVBaseURL:            osv.DefaultBaseURL,
		KEVURLs:               []string{cvefeeds.DefaultKEVURL, cvefeeds.KEVMirrorURL},
		EPSSURL:               cvefeeds.DefaultEPSSURL,
		FullSyncInterval:      7 * 24 * time.Hour,
		IncrementalMaxChanges: 5000,
		Workers:               4,
		BatchSize:             250,
	}
}

// AdvisoriesChangedFunc is called after an OSV sync that marked at least
// one (distro, release, source package) dirty in advisory_changes.
type AdvisoriesChangedFunc func(ctx context.Context, feed string, dirty int) error

type Syncer struct {
	Store *store.Store
	HTTP  *http.Client
	Cfg   Config
	// OnAdvisoriesChanged is the matcher trigger. The jobs package sets it
	// to enqueue an advisory_rematch job; nil in one-shot CLI runs (the
	// dirty rows stay in advisory_changes either way).
	OnAdvisoriesChanged AdvisoriesChangedFunc
}

// userAgent identifies every feed request (OSV, KEV, EPSS).
const userAgent = "upkeep.sh-worker/1 (self-hosted vulnerability feed sync; +https://upkeep.sh)"

func (s *Syncer) osvClient() *osv.Client {
	return &osv.Client{BaseURL: s.Cfg.OSVBaseURL, HTTP: s.httpClient(), UserAgent: userAgent}
}

func (s *Syncer) httpClient() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return http.DefaultClient
}
