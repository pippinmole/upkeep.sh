// Package netguard makes outbound HTTP requests to user-supplied URLs
// (webhooks and future notifiers) without letting them reach the
// platform's own network: server-side request forgery protection.
//
// Rules (Guard defaults):
//   - https only; no userinfo in the URL; port 443 or 8443 only (so the
//     platform can't be used to probe arbitrary services).
//   - Every address the host name resolves to must be a public unicast
//     address. Loopback, RFC 1918 private, CGNAT, link-local (incl. the
//     169.254.169.254 cloud metadata service), unique-local IPv6 (incl.
//     fd00:ec2::254), multicast, unspecified, reserved, documentation and
//     benchmarking ranges, and IPv6 prefixes that embed an IPv4 address
//     (IPv4-mapped, NAT64, 6to4, Teredo) are refused.
//   - The check runs at dial time, on the exact IP being connected to: the
//     guard resolves the name itself, refuses the request if ANY resolved
//     address is blocked, and dials the checked IP (never re-resolving), so
//     DNS rebinding between a validation lookup and the connection can't
//     sneak a private address in. A net.Dialer Control hook re-checks the
//     socket's address as defense in depth.
//   - Environment proxies are ignored (a proxy would move the connection
//     out of the guard's sight).
//   - Redirects: only to the same scheme, host and port, at most 3, each
//     re-checked by the dialer. A redirect to another host is refused.
//
// Dev escape hatch: SW_NOTIFY_ALLOW_PRIVATE_NETWORKS=true (FromEnv) allows
// private/loopback addresses, plain http and any port, for pointing a
// webhook at a receiver on your own machine. Off by default; the worker
// logs a warning when it is on. Never set it in production.
package netguard

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// EnvAllowPrivate is the dev-only escape hatch (see package doc).
const EnvAllowPrivate = "SW_NOTIFY_ALLOW_PRIVATE_NETWORKS"

// ErrBlocked wraps every refusal, so callers can treat it as permanent.
var ErrBlocked = errors.New("destination not allowed")

func blocked(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrBlocked, fmt.Sprintf(format, a...))
}

// Guard holds the outbound policy. The zero value is the strict default.
type Guard struct {
	// AllowPrivate permits non-public addresses, plain http and any port.
	// Dev/test only.
	AllowPrivate bool
	// AllowedPorts overrides the default {443, 8443} (ignored when
	// AllowPrivate).
	AllowedPorts []int
	// Lookup resolves a host name; nil = net.DefaultResolver. Tests inject
	// one to simulate DNS answers (rebinding).
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// TLSConfig is used for https (nil = system roots). Tests inject the
	// httptest server's CA.
	TLSConfig *tls.Config
}

// FromEnv returns the default guard, relaxed only if EnvAllowPrivate is true.
func FromEnv() *Guard {
	v, _ := strconv.ParseBool(os.Getenv(EnvAllowPrivate))
	return &Guard{AllowPrivate: v}
}

var defaultPorts = []int{443, 8443}

// CheckURL validates a URL's shape (scheme, userinfo, port) without
// resolving it. Use it to validate configuration.
func (g *Guard) CheckURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("invalid URL: missing host")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !g.AllowPrivate {
			return nil, blocked("only https URLs are allowed")
		}
	default:
		return nil, blocked("unsupported URL scheme %q", u.Scheme)
	}
	if u.User != nil {
		return nil, blocked("credentials in the URL are not allowed")
	}
	if !g.AllowPrivate {
		port := 443
		if p := u.Port(); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil {
				return nil, fmt.Errorf("invalid URL port %q", p)
			}
			port = n
		}
		allowed := g.AllowedPorts
		if len(allowed) == 0 {
			allowed = defaultPorts
		}
		if !slices.Contains(allowed, port) {
			return nil, blocked("port %d is not allowed (allowed: %v)", port, allowed)
		}
		// A literal address is checked here too, for an early, clear error.
		if a, err := netip.ParseAddr(strings.Trim(u.Hostname(), "[]")); err == nil {
			if err := CheckAddr(a); err != nil {
				return nil, err
			}
		}
	}
	return u, nil
}

// Resolve resolves host and checks every address; it fails if any one is
// blocked (a name that points at both public and private addresses is
// treated as hostile).
func (g *Guard) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return []netip.Addr{a.Unmap()}, g.check(a)
	}
	lookup := g.Lookup
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	addrs, err := lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %s: no addresses", host)
	}
	for i, a := range addrs {
		addrs[i] = a.Unmap()
		if err := g.check(addrs[i]); err != nil {
			return nil, fmt.Errorf("%s resolves to %s: %w", host, addrs[i], err)
		}
	}
	return addrs, nil
}

func (g *Guard) check(a netip.Addr) error {
	if g.AllowPrivate {
		return nil
	}
	return CheckAddr(a)
}

// DialContext resolves, checks and dials the checked address.
func (g *Guard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addrs, err := g.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{
		Timeout: 5 * time.Second,
		// Defense in depth: check the socket's actual peer address.
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return blocked("unparseable dial address %q", address)
			}
			return g.check(ap.Addr().Unmap())
		},
	}
	var lastErr error
	for _, a := range addrs {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// MaxRedirects is the number of same-origin redirects followed.
const MaxRedirects = 3

// Client returns an HTTP client that only connects to allowed addresses.
// timeout bounds the whole request including reading the response.
func (g *Guard) Client(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy:                 nil, // never an environment proxy
		DialContext:           g.DialContext,
		TLSClientConfig:       g.TLSConfig,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > MaxRedirects {
				return blocked("more than %d redirects", MaxRedirects)
			}
			orig := via[0].URL
			if req.URL.Scheme != orig.Scheme || !strings.EqualFold(req.URL.Host, orig.Host) {
				return blocked("redirect to a different origin (%s)", req.URL.Redacted())
			}
			if _, err := g.CheckURL(req.URL.String()); err != nil {
				return err
			}
			return nil
		},
	}
}

// Prefixes refused on top of netip's classification helpers.
var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8",         // "this network"
		"100.64.0.0/10",     // CGNAT (also Alibaba metadata 100.100.100.200)
		"192.0.0.0/24",      // IETF protocol assignments
		"192.0.2.0/24",      // TEST-NET-1
		"198.18.0.0/15",     // benchmarking
		"198.51.100.0/24",   // TEST-NET-2
		"203.0.113.0/24",    // TEST-NET-3
		"240.0.0.0/4",       // reserved, incl. 255.255.255.255
		"64:ff9b::/96",      // NAT64 (embeds IPv4)
		"64:ff9b:1::/48",    // local-use NAT64
		"100::/64",          // discard-only
		"2001::/32",         // Teredo (embeds IPv4)
		"2001:db8::/32",     // documentation
		"2002::/16",         // 6to4 (embeds IPv4)
		"fc00::/7",          // unique local (IsPrivate covers it too)
		"fec0::/10",         // deprecated site-local
		"::ffff:0:0/96",     // IPv4-mapped (unmapped before checking anyway)
		"::/128", "::1/128", // unspecified, loopback
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// CheckAddr returns an ErrBlocked error unless a is a public unicast address.
func CheckAddr(a netip.Addr) error {
	a = a.Unmap()
	switch {
	case !a.IsValid():
		return blocked("invalid address")
	case a.IsLoopback():
		return blocked("%s is a loopback address", a)
	case a.IsPrivate():
		return blocked("%s is a private address", a)
	case a.IsLinkLocalUnicast():
		return blocked("%s is a link-local address (cloud metadata lives here)", a)
	case a.IsUnspecified():
		return blocked("%s is unspecified", a)
	case a.IsMulticast(), a.IsLinkLocalMulticast(), a.IsInterfaceLocalMulticast():
		return blocked("%s is a multicast address", a)
	case !a.IsGlobalUnicast():
		return blocked("%s is not a global unicast address", a)
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return blocked("%s is in reserved range %s", a, p)
		}
	}
	return nil
}
