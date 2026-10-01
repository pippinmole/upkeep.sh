// Package imagesbom obtains the server's package list for one container
// image key (image_id, os, arch, variant) from its registry's SBOM
// attestation, else by pulling and scanning the image (server-side Syft,
// internal/imagescan, scan.go), and stores it
// (docs/tasks/phase-2a-image-vulns.md "Worker: image_sbom",
// docs/decisions/container-image-vulnerabilities.md). The image_sbom River
// job (internal/jobs) runs it; `worker image-sbom` runs it in the
// foreground.
//
//	image key ── repo digests (host_images, any host) ──> registry.FetchSBOM
//	  ── sbom.Parse ──> purl.Map (image OS, distro_releases) ──> store.WriteImageSBOM
//	                                                             (source attestation, owner NULL)
//
// Without an attestation, Run hands the key over to the scan (Outcome.Scan;
// jobs enqueues image_scan, whose Fetcher.Scan pulls the image and runs
// Syft, storing the list with source server-syft through the same path).
//
// A failure is recorded on image_sbom_state (store.RecordImageSBOMFailure)
// as unavailable (no timed retry: something else has to change) or error
// (retried on a capped exponential backoff by the sweep). An ok list is
// never refetched: image content is immutable.
package imagesbom

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/imagescan"
	"github.com/pippinmole/upkeep.sh/server/internal/purl"
	"github.com/pippinmole/upkeep.sh/server/internal/registry"
	"github.com/pippinmole/upkeep.sh/server/internal/sbom"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

// Retry backoff defaults for status error: RetryBase * 2^attempts, capped.
const (
	DefaultRetryBase = 30 * time.Minute
	DefaultRetryMax  = 24 * time.Hour
)

// Config configures a Fetcher.
type Config struct {
	// Enabled: outbound image fetching (SW_IMAGE_FETCH_ENABLED, on by
	// default). Off for air-gapped installs: every attempt records
	// store.SBOMReasonFetchDisabled and nothing is contacted.
	Enabled bool
	// Registry is the shared registry client (required when Enabled).
	Registry *registry.Client
	// Scanner pulls and scans images without an attestation (nil =
	// server-side scanning off, SW_IMAGE_SCAN_ENABLED=false: such images
	// stay unavailable with store.SBOMReasonNoAttestation).
	Scanner *imagescan.Scanner
	// RetryBase / RetryMax: backoff for status error (0 = defaults).
	RetryBase, RetryMax time.Duration
	// Now is the clock (nil = time.Now).
	Now func() time.Time
}

// Fetcher runs attempts. Safe for concurrent use.
type Fetcher struct {
	Store *store.Store
	Cfg   Config
	// AfterWrite runs inside the list's write transaction
	// (jobs.EnqueueAfterImageSBOM: match_versions for new versions).
	AfterWrite func(ctx context.Context, tx pgx.Tx, res store.ImageSBOMResult) error
}

// Outcome is what one attempt did, for logs and tests.
type Outcome struct {
	Key store.ImageKey
	// Status: store.SBOMStatusOK / Unavailable / Error, or "skipped"
	// (the key already has an ok server list).
	Status string
	Reason string
	// Digests are the repo digests the attempt considered.
	Digests []string
	// Set when ok.
	Ref                   string // the repo digest the SBOM came from
	Via                   string // registry.ViaAttestationManifest | ViaReferrers | ViaPull
	ToolName, ToolVersion string
	Packages, Unmapped    int
	OS                    purl.OSRelease
	Release               string
	// Scan: no attestation, and the key was handed over to the
	// server-side scan (Run only); the caller enqueues it.
	Scan bool
	// Set for error: when the sweep retries.
	NextAttemptAt *time.Time
	// Err is the underlying error of a failed attempt (logged, not stored).
	Err error
}

// StatusSkipped: the key already had an ok server list.
const StatusSkipped = "skipped"

func (f *Fetcher) now() time.Time {
	if f.Cfg.Now != nil {
		return f.Cfg.Now()
	}
	return time.Now()
}

// Run makes one attempt at key's server list. The returned error is for
// failures of our own (database); registry and document problems are an
// Outcome, recorded on image_sbom_state.
func (f *Fetcher) Run(ctx context.Context, key store.ImageKey) (Outcome, error) {
	out := Outcome{Key: key}
	st, err := f.Store.ServerImageSBOMState(ctx, key)
	if err != nil {
		return out, err
	}
	if st != nil && st.Status == store.SBOMStatusOK {
		out.Status = StatusSkipped
		return out, nil
	}
	if !f.Cfg.Enabled {
		return f.fail(ctx, out, st, failure{status: store.SBOMStatusUnavailable, reason: store.SBOMReasonFetchDisabled})
	}
	if out.Digests, err = f.Store.ImageRepoDigests(ctx, key); err != nil {
		return out, err
	}
	if len(out.Digests) == 0 {
		// Never enqueued without one; a host may have dropped it since.
		return f.fail(ctx, out, st, failure{status: store.SBOMStatusUnavailable, reason: store.SBOMReasonPrivate})
	}

	var fails []failure
	for _, d := range out.Digests {
		ref, err := registry.ParseRepoDigest(d)
		if err != nil {
			fails = append(fails, classify(&registry.Error{Kind: registry.KindDenied, Err: err}))
			continue
		}
		s, err := f.Cfg.Registry.FetchSBOM(ctx, ref, registry.Platform{OS: key.OS, Architecture: key.Arch, Variant: key.Variant}, key.ImageID)
		if err != nil {
			if ctx.Err() != nil {
				return out, ctx.Err() // shutting down or timed out: River retries
			}
			fails = append(fails, classify(err))
			continue
		}
		out.Ref, out.Via = d, s.Via
		doc, err := sbom.Parse(s.Format, s.Document)
		if err != nil {
			fails = append(fails, failure{
				status: store.SBOMStatusUnavailable, rank: 3,
				reason: "registry SBOM could not be read", err: err,
			})
			continue
		}
		if err := f.store(ctx, &out, doc, store.SBOMSourceAttestation); err != nil {
			return out, err
		}
		out.Status = store.SBOMStatusOK
		return out, nil
	}
	fl := worst(fails)
	if fl.reason == store.SBOMReasonNoAttestation && f.Cfg.Scanner != nil {
		fl.handover, out.Scan = true, true
	}
	return f.fail(ctx, out, st, fl)
}

// store maps and writes one package list.
func (f *Fetcher) store(ctx context.Context, out *Outcome, doc *sbom.Document, source string) error {
	ix, err := f.Store.DistroReleaseIndex(ctx)
	if err != nil {
		return err
	}
	in := store.ImageSBOMInput{
		Key: out.Key, Source: source,
		ToolName: doc.ToolName, ToolVersion: doc.ToolVersion, GeneratedAt: doc.Created,
		OS: doc.OS, AfterWrite: f.AfterWrite,
	}
	if doc.OS.ID != "" {
		in.Release = purl.ReleaseFor(doc.OS, ix)
	}
	for _, p := range doc.Packages {
		m, err := purl.Map(p.PURL, doc.OS, ix)
		if err != nil {
			out.Unmapped++
			continue
		}
		in.Packages = append(in.Packages, store.ImagePackage{Package: m, Paths: p.Paths})
	}
	out.Unmapped += doc.Skipped
	res, err := f.Store.WriteImageSBOM(ctx, in)
	if err != nil {
		return fmt.Errorf("write image sbom: %w", err)
	}
	out.ToolName, out.ToolVersion, out.OS, out.Release, out.Packages =
		doc.ToolName, doc.ToolVersion, doc.OS, in.Release, res.Packages
	return nil
}

// fail records fl on the server row and fills the outcome.
func (f *Fetcher) fail(ctx context.Context, out Outcome, st *store.ImageSBOMState, fl failure) (Outcome, error) {
	out.Status, out.Reason, out.Err = fl.status, fl.reason, fl.err
	if fl.status == store.SBOMStatusError {
		attempts := 0
		if st != nil {
			attempts = st.Attempts
		}
		next := f.now().Add(f.backoff(attempts))
		if fl.retryAt.After(next) {
			next = fl.retryAt
		}
		out.NextAttemptAt = &next
	}
	_, err := f.Store.RecordImageSBOMFailure(ctx, store.ImageSBOMFailure{
		Key: out.Key, Status: out.Status, Reason: out.Reason, NextAttemptAt: out.NextAttemptAt,
		Handover: fl.handover,
	})
	return out, err
}

// backoff is RetryBase * 2^attempts, capped at RetryMax.
func (f *Fetcher) backoff(attempts int) time.Duration {
	base, maxd := f.Cfg.RetryBase, f.Cfg.RetryMax
	if base <= 0 {
		base = DefaultRetryBase
	}
	if maxd <= 0 {
		maxd = DefaultRetryMax
	}
	d := base
	for i := 0; i < attempts && d < maxd; i++ {
		d *= 2
	}
	return min(d, maxd)
}
