package registry

import (
	"errors"
	"fmt"
	"time"
)

// Errors are classified by what the caller should do next, not by HTTP
// status: Kind says whether trying again later can help.

// ErrorKind classifies a failed fetch.
type ErrorKind int

const (
	// KindTransient: network error, timeout, 5xx, unexpected status, a
	// digest mismatch. Worth retrying later.
	KindTransient ErrorKind = iota
	// KindRateLimited: 429, or the registry is backing off after one.
	// Retry at RetryAt.
	KindRateLimited
	// KindDenied: 401/403 on anonymous access, 404, or a destination
	// netguard refuses (private address, disallowed port or scheme). The
	// image is private or local as far as the server can tell.
	KindDenied
	// KindNoAttestation: the image is reachable but carries no SBOM
	// attestation (neither BuildKit attestation manifests nor OCI
	// referrers).
	KindNoAttestation
	// KindTooLarge: a manifest or SBOM exceeded its size cap.
	KindTooLarge
	// KindMismatch: the registry's content doesn't belong to the image
	// (platform missing from the index, or the image id matches none of
	// the index, manifest or config digests).
	KindMismatch
)

func (k ErrorKind) String() string {
	switch k {
	case KindRateLimited:
		return "rate limited"
	case KindDenied:
		return "denied"
	case KindNoAttestation:
		return "no attestation"
	case KindTooLarge:
		return "too large"
	case KindMismatch:
		return "mismatch"
	default:
		return "transient"
	}
}

// Error is every error the client returns for a registry interaction.
type Error struct {
	Kind ErrorKind
	Host string
	// Status is the HTTP status that caused it (0 = none).
	Status int
	// RetryAt is set for KindRateLimited: when the registry may be asked
	// again (from Retry-After, else the client's default backoff).
	RetryAt time.Time
	Err     error
}

func (e *Error) Error() string {
	if e.Host == "" {
		return fmt.Sprintf("registry: %s: %v", e.Kind, e.Err)
	}
	return fmt.Sprintf("registry %s: %s: %v", e.Host, e.Kind, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// KindOf returns err's kind; errors that aren't *Error are transient.
func KindOf(err error) ErrorKind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return KindTransient
}

// RetryAt returns when a rate-limited err may be retried (zero if none).
func RetryAt(err error) time.Time {
	var e *Error
	if errors.As(err, &e) {
		return e.RetryAt
	}
	return time.Time{}
}

func newErr(kind ErrorKind, host string, format string, a ...any) *Error {
	return &Error{Kind: kind, Host: host, Err: fmt.Errorf(format, a...)}
}
