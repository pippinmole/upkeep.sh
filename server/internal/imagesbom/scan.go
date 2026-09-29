package imagesbom

import (
	"context"
	"errors"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/imagescan"
	"github.com/pippinmole/upkeep.sh/server/internal/registry"
	"github.com/pippinmole/upkeep.sh/server/internal/sbom"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

// ViaPull: the list came from pulling the image and scanning it
// (Outcome.Via for source server-syft).
const ViaPull = "pull"

// Reasons of failed scans. Shown to users as is.
const (
	reasonScanTooLarge    = "image is larger than this server's scan size limit"
	reasonScanUnsupported = "image layers are in a format the server can't scan"
	reasonScanMemory      = "image scan needs more memory than this server's limit"
	reasonScanTimeout     = "image scan took longer than this server's time limit, will retry"
	reasonScanFailed      = "image scan failed on the server, will retry"
)

// Scan makes one server-side scan attempt at key's list: the image_scan
// job, after Run found no attestation. It pulls the image by each repo
// digest in turn until one scan works and stores the list with source
// server-syft. A key that meanwhile got an ok list (an attestation, or
// another scan) is skipped; a failure never replaces an ok list.
func (f *Fetcher) Scan(ctx context.Context, key store.ImageKey) (Outcome, error) {
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
	if f.Cfg.Scanner == nil {
		return f.fail(ctx, out, st, failure{status: store.SBOMStatusUnavailable, reason: store.SBOMReasonNoAttestation})
	}
	if out.Digests, err = f.Store.ImageRepoDigests(ctx, key); err != nil {
		return out, err
	}
	if len(out.Digests) == 0 {
		return f.fail(ctx, out, st, failure{status: store.SBOMStatusUnavailable, reason: store.SBOMReasonPrivate})
	}

	var fails []failure
	for _, d := range out.Digests {
		ref, err := registry.ParseRepoDigest(d)
		if err != nil {
			fails = append(fails, classify(&registry.Error{Kind: registry.KindDenied, Err: err}))
			continue
		}
		res, err := f.Cfg.Scanner.Scan(ctx, ref, registry.Platform{OS: key.OS, Architecture: key.Arch, Variant: key.Variant}, key.ImageID)
		if err != nil {
			if ctx.Err() != nil {
				return out, ctx.Err() // shutting down or the job timed out: River retries
			}
			fails = append(fails, classifyScan(err))
			continue
		}
		out.Ref, out.Via = d, ViaPull
		doc := sbom.FromEntries(res.ToolName, res.ToolVersion, time.Now().UTC(), res.OS, res.Packages)
		doc.Skipped += res.NoPURL
		if err := f.store(ctx, &out, doc, store.SBOMSourceServerSyft); err != nil {
			return out, err
		}
		out.Status = store.SBOMStatusOK
		return out, nil
	}
	return f.fail(ctx, out, st, worst(fails))
}

// classifyScan turns a scan error into the failure to record. Registry
// errors are as for attestations, except that a layer over the size cap
// is the scan's own limit.
//
//	too large, unsupported layers,   unavailable (no timed retry: the
//	  over the memory limit            image or the limits must change)
//	timeout, anything else           error, retried on backoff
func classifyScan(err error) failure {
	var e *imagescan.Error
	if !errors.As(err, &e) {
		if registry.KindOf(err) == registry.KindTooLarge {
			return failure{status: store.SBOMStatusUnavailable, rank: 2, err: err, reason: reasonScanTooLarge}
		}
		return classify(err)
	}
	switch e.Kind {
	case imagescan.KindTooLarge:
		return failure{status: store.SBOMStatusUnavailable, rank: 2, err: err, reason: reasonScanTooLarge}
	case imagescan.KindUnsupported:
		return failure{status: store.SBOMStatusUnavailable, rank: 2, err: err, reason: reasonScanUnsupported}
	case imagescan.KindMemory:
		return failure{status: store.SBOMStatusUnavailable, rank: 2, err: err, reason: reasonScanMemory}
	case imagescan.KindTimeout:
		return failure{status: store.SBOMStatusError, rank: 0, err: err, reason: reasonScanTimeout}
	default:
		return failure{status: store.SBOMStatusError, rank: 0, err: err, reason: reasonScanFailed}
	}
}
