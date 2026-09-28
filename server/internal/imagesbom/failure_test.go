package imagesbom

import (
	"errors"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/registry"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

func TestClassifyAndWorst(t *testing.T) {
	at := time.Date(2026, 9, 28, 13, 0, 0, 0, time.UTC)
	denied := classify(&registry.Error{Kind: registry.KindDenied, Status: 404, Err: errors.New("x")})
	none := classify(&registry.Error{Kind: registry.KindNoAttestation, Err: errors.New("x")})
	limited := classify(&registry.Error{Kind: registry.KindRateLimited, Host: "registry-1.docker.io", RetryAt: at, Err: errors.New("x")})
	down := classify(&registry.Error{Kind: registry.KindTransient, Host: "ghcr.io", Status: 502, Err: errors.New("x")})

	if denied.status != store.SBOMStatusUnavailable || denied.reason != store.SBOMReasonPrivate {
		t.Errorf("denied = %+v", denied)
	}
	if none.reason != store.SBOMReasonNoAttestation {
		t.Errorf("none = %+v", none)
	}
	if limited.status != store.SBOMStatusError || !limited.retryAt.Equal(at) {
		t.Errorf("limited = %+v", limited)
	}
	if down.reason != "registry ghcr.io returned HTTP 502, will retry" {
		t.Errorf("down = %q", down.reason)
	}
	// Retryable beats everything; no attestation beats private.
	if w := worst([]failure{denied, none, limited}); w.status != store.SBOMStatusError {
		t.Errorf("worst = %+v", w)
	}
	if w := worst([]failure{denied, none}); w.reason != store.SBOMReasonNoAttestation {
		t.Errorf("worst = %+v", w)
	}
}

func TestBackoff(t *testing.T) {
	f := &Fetcher{}
	for attempts, want := range map[int]time.Duration{0: 30 * time.Minute, 1: time.Hour, 3: 4 * time.Hour, 10: 24 * time.Hour, 100: 24 * time.Hour} {
		if got := f.backoff(attempts); got != want {
			t.Errorf("backoff(%d) = %v, want %v", attempts, got, want)
		}
	}
}
