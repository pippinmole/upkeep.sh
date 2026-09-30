package imagesbom

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/registry"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

// failure is one repo digest's failed attempt, as it would be recorded.
type failure struct {
	status  string // store.SBOMStatusUnavailable | SBOMStatusError
	reason  string
	retryAt time.Time // error only: not before (a registry's Retry-After)
	err     error
	rank    int // worst() picks the lowest
	// handover: not a failure of this attempt but the hand-over to the
	// server-side scan (store.ImageSBOMFailure.Handover).
	handover bool
}

// Reasons besides the store.SBOMReason* ones. Shown to users as is.
const (
	reasonTooLarge = "registry SBOM is larger than this server's size limit"
	reasonMismatch = "registry image doesn't match this image (platform or digest)"
)

// classify turns a registry error into the failure to record:
//
//	rate limited, transient   error, retried on backoff (Retry-After respected)
//	no attestation            unavailable: SBOMReasonNoAttestation (server-side Syft's work list)
//	too large, mismatch       unavailable
//	denied (401/403/404, a    unavailable: SBOMReasonPrivate (the agent's work)
//	  private address, a
//	  malformed repo digest)
func classify(err error) failure {
	var e *registry.Error
	host := "registry"
	if errors.As(err, &e) && e.Host != "" {
		host = "registry " + e.Host
	}
	switch registry.KindOf(err) {
	case registry.KindRateLimited:
		return failure{status: store.SBOMStatusError, rank: 0, err: err, retryAt: registry.RetryAt(err),
			reason: host + " is rate limiting requests, will retry"}
	case registry.KindTransient:
		return failure{status: store.SBOMStatusError, rank: 0, err: err, reason: transientReason(host, e)}
	case registry.KindNoAttestation:
		return failure{status: store.SBOMStatusUnavailable, rank: 1, err: err, reason: store.SBOMReasonNoAttestation}
	case registry.KindTooLarge:
		return failure{status: store.SBOMStatusUnavailable, rank: 2, err: err, reason: reasonTooLarge}
	case registry.KindMismatch:
		return failure{status: store.SBOMStatusUnavailable, rank: 4, err: err, reason: reasonMismatch}
	default: // KindDenied
		return failure{status: store.SBOMStatusUnavailable, rank: 5, err: err, reason: store.SBOMReasonPrivate}
	}
}

func transientReason(host string, e *registry.Error) string {
	switch {
	case e != nil && e.Status != 0:
		return fmt.Sprintf("%s returned HTTP %d, will retry", host, e.Status)
	case e != nil && strings.Contains(e.Error(), "digest mismatch"):
		return host + " returned content that failed digest verification, will retry"
	default:
		return host + " could not be reached, will retry"
	}
}

// worst picks the failure to record when every repo digest failed: one
// worth retrying wins (another registry may be down for a moment), then
// the most specific reason. An unreadable document ranks 3.
func worst(fails []failure) failure {
	best := fails[0]
	for _, f := range fails[1:] {
		if f.rank < best.rank || (f.rank == best.rank && f.retryAt.After(best.retryAt)) {
			best = f
		}
	}
	return best
}
