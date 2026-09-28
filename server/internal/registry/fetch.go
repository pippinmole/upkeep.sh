package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/netguard"
)

// Media types accepted for manifests: OCI and Docker v2, index and
// single-platform.
const (
	MediaTypeOCIIndex       = "application/vnd.oci.image.index.v1+json"
	MediaTypeOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaTypeDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	acceptManifests         = MediaTypeOCIIndex + ", " + MediaTypeDockerList + ", " + MediaTypeOCIManifest + ", " + MediaTypeDockerManifest
)

// getManifest GETs a manifest or index by digest and verifies its content
// digest.
func (c *Client) getManifest(ctx context.Context, ref Ref, digest string) ([]byte, error) {
	body, _, err := c.get(ctx, ref, "/manifests/"+digest, acceptManifests, c.cfg.MaxManifestBytes, c.cfg.RequestTimeout)
	if err != nil {
		return nil, err
	}
	return body, verifyDigest(ref.Host, digest, body)
}

// getBlob GETs a blob by digest (following the redirect to a CDN) and
// verifies its content digest.
func (c *Client) getBlob(ctx context.Context, ref Ref, digest string, size int64) ([]byte, error) {
	if size > c.cfg.MaxBlobBytes {
		return nil, newErr(KindTooLarge, ref.Host, "blob %s is %d bytes, over the %d byte limit", digest, size, c.cfg.MaxBlobBytes)
	}
	body, _, err := c.get(ctx, ref, "/blobs/"+digest, "", c.cfg.MaxBlobBytes, c.cfg.BlobTimeout)
	if err != nil {
		return nil, err
	}
	return body, verifyDigest(ref.Host, digest, body)
}

func verifyDigest(host, want string, body []byte) error {
	sum := sha256.Sum256(body)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != want {
		return newErr(KindTransient, host, "content digest mismatch: asked for %s, got %s", want, got)
	}
	return nil
}

// get GETs https://<host>/v2/<repository><path>, running the token flow
// once on a 401.
func (c *Client) get(ctx context.Context, ref Ref, path, accept string, maxBytes int64, timeout time.Duration) ([]byte, http.Header, error) {
	u := "https://" + ref.Host + "/v2/" + ref.Repository + path
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, nil, newErr(KindTransient, ref.Host, "request: %v", err)
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if tok := c.cachedToken(ref); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		body, hdr, err := c.send(ctx, ref.Host, req, maxBytes, timeout)
		var e *Error
		if attempt == 0 && errors.As(err, &e) && e.Status == http.StatusUnauthorized {
			if _, err := c.fetchToken(ctx, ref, hdr.Get("WWW-Authenticate")); err != nil {
				return nil, nil, err
			}
			continue
		}
		return body, hdr, err
	}
}

// send runs one request against host (the registry the request is on
// behalf of, for backoff) and reads at most maxBytes of a 200 response.
// Non-200 statuses become *Error with Status set; the headers are
// returned with them (the 401 challenge).
func (c *Client) send(ctx context.Context, host string, req *http.Request, maxBytes int64, timeout time.Duration) ([]byte, http.Header, error) {
	if until, ok := c.backedOff(host); ok {
		return nil, nil, &Error{Kind: KindRateLimited, Host: host, RetryAt: until,
			Err: errors.New("backing off after a 429")}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req = req.WithContext(ctx)
	if c.cfg.UserAgent != "" {
		req.Header.Set("User-Agent", c.cfg.UserAgent)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, netguard.ErrBlocked) {
			return nil, nil, &Error{Kind: KindDenied, Host: host, Err: err}
		}
		return nil, nil, &Error{Kind: KindTransient, Host: host, Err: err}
	}
	defer resp.Body.Close()

	switch s := resp.StatusCode; {
	case s == http.StatusOK:
	case s == http.StatusTooManyRequests:
		until := c.cfg.Now().Add(retryAfter(resp.Header.Get("Retry-After"), c.cfg.Now(), c.cfg.RateLimitBackoff))
		c.backOff(host, until)
		return nil, resp.Header, &Error{Kind: KindRateLimited, Host: host, Status: s, RetryAt: until,
			Err: fmt.Errorf("GET %s: %s", req.URL.Redacted(), resp.Status)}
	case s == http.StatusUnauthorized, s == http.StatusForbidden, s == http.StatusNotFound:
		return nil, resp.Header, &Error{Kind: KindDenied, Host: host, Status: s,
			Err: fmt.Errorf("GET %s: %s", req.URL.Redacted(), resp.Status)}
	default:
		return nil, resp.Header, &Error{Kind: KindTransient, Host: host, Status: s,
			Err: fmt.Errorf("GET %s: %s", req.URL.Redacted(), resp.Status)}
	}

	if resp.ContentLength > maxBytes {
		return nil, nil, newErr(KindTooLarge, host, "response of %d bytes, over the %d byte limit", resp.ContentLength, maxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, nil, &Error{Kind: KindTransient, Host: host, Err: fmt.Errorf("read %s: %w", req.URL.Redacted(), err)}
	}
	if int64(len(body)) > maxBytes {
		return nil, nil, newErr(KindTooLarge, host, "response over the %d byte limit", maxBytes)
	}
	return body, resp.Header, nil
}

// retryAfter parses a Retry-After header (seconds or an HTTP date) into a
// wait, clamped to [1s, MaxRateLimitBackoff]; fallback when absent or
// unparseable.
func retryAfter(h string, now time.Time, fallback time.Duration) time.Duration {
	d := fallback
	if n, err := strconv.Atoi(h); err == nil {
		d = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(h); err == nil {
		d = t.Sub(now)
	}
	return min(max(d, time.Second), MaxRateLimitBackoff)
}
