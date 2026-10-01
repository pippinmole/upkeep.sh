package registry

import (
	"cmp"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/netguard"
)

// Defaults for Config's zero values.
const (
	DefaultMaxManifestBytes = 4 << 20  // an index or manifest; real ones are a few KiB
	DefaultMaxBlobBytes     = 64 << 20 // an SBOM document (postgres:17's SPDX is ~6 MiB)
	DefaultRequestTimeout   = 30 * time.Second
	DefaultBlobTimeout      = 2 * time.Minute
	DefaultLayerTimeout     = 10 * time.Minute // one image layer (server-side Syft)
	DefaultRateLimitBackoff = 10 * time.Minute // after a 429 without Retry-After
	MaxRateLimitBackoff     = 6 * time.Hour    // cap on what a Retry-After can ask for
	// MaxRedirects bounds the redirects of one request (a blob GET is
	// normally one hop to a CDN).
	MaxRedirects = 5
)

// Config configures a Client.
type Config struct {
	// Guard decides which addresses may be connected to; nil =
	// netguard.FromEnv(). A registry may be on any port, but every
	// address it resolves to must be public; redirect targets must also
	// pass Guard.CheckURL (https, allowed ports).
	Guard *netguard.Guard
	// UserAgent is sent with every request.
	UserAgent string
	// DockerHubUsername / DockerHubToken: optional platform-wide Docker
	// Hub credentials (a personal access token), used only for Docker
	// Hub's token endpoint and only to raise the anonymous pull rate
	// limit. Never sent to any other registry.
	DockerHubUsername, DockerHubToken string
	// Size caps (0 = default).
	MaxManifestBytes int64
	MaxBlobBytes     int64
	// Per-request timeouts (0 = default): manifests and tokens, blobs.
	RequestTimeout, BlobTimeout time.Duration
	// LayerTimeout bounds one image layer download (0 = default).
	LayerTimeout time.Duration
	// RateLimitBackoff is how long a registry is left alone after a 429
	// without a Retry-After (0 = default).
	RateLimitBackoff time.Duration
	// Now is the clock (nil = time.Now); tests inject one.
	Now func() time.Time
}

// Client fetches SBOM attestations. It is safe for concurrent use and
// meant to be shared by all image_sbom workers of a process, so the
// per-registry backoff and token cache are shared too.
type Client struct {
	cfg  Config
	http *http.Client

	mu      sync.Mutex
	backoff map[string]time.Time // registry host -> don't contact before
	tokens  map[tokenKey]token
}

// New returns a Client for cfg.
func New(cfg Config) *Client {
	if cfg.Guard == nil {
		cfg.Guard = netguard.FromEnv()
	}
	cfg.MaxManifestBytes = cmp.Or(cfg.MaxManifestBytes, DefaultMaxManifestBytes)
	cfg.MaxBlobBytes = cmp.Or(cfg.MaxBlobBytes, DefaultMaxBlobBytes)
	cfg.RequestTimeout = cmp.Or(cfg.RequestTimeout, DefaultRequestTimeout)
	cfg.BlobTimeout = cmp.Or(cfg.BlobTimeout, DefaultBlobTimeout)
	cfg.LayerTimeout = cmp.Or(cfg.LayerTimeout, DefaultLayerTimeout)
	cfg.RateLimitBackoff = cmp.Or(cfg.RateLimitBackoff, DefaultRateLimitBackoff)
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Client{
		cfg:     cfg,
		http:    newHTTPClient(cfg.Guard),
		backoff: map[string]time.Time{},
		tokens:  map[tokenKey]token{},
	}
}

// newHTTPClient is netguard's client with one difference: redirects to
// another origin are allowed (registries send blob GETs to a CDN), each
// target re-checked by CheckURL (scheme, port, literal address) and, when
// dialed, by the guard's dialer (every resolved address). The
// Authorization header is dropped on a redirect to another origin, so
// registry tokens never reach the CDN. Timeouts are per request, via the
// context.
func newHTTPClient(g *netguard.Guard) *http.Client {
	tr := &http.Transport{
		Proxy:                 nil, // never an environment proxy
		DialContext:           g.DialContext,
		TLSClientConfig:       g.TLSConfig,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: DefaultRequestTimeout,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       60 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > MaxRedirects {
				return fmt.Errorf("more than %d redirects", MaxRedirects)
			}
			if _, err := g.CheckURL(req.URL.String()); err != nil {
				return err
			}
			// Go keeps Authorization on a redirect to the same host name
			// on another port; a token is only for the registry itself.
			if !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
				req.Header.Del("Authorization")
			}
			return nil
		},
	}
}

// backedOff returns when host may be contacted again, if it is backing off.
func (c *Client) backedOff(host string) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	until, ok := c.backoff[host]
	if ok && c.cfg.Now().Before(until) {
		return until, true
	}
	delete(c.backoff, host)
	return time.Time{}, false
}

// backOff makes host wait until at least until.
func (c *Client) backOff(host string, until time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if until.After(c.backoff[host]) {
		c.backoff[host] = until
	}
}
