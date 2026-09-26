package collector

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// publicIPTimeout bounds each lookup so a dead network or slow upstream can
// never meaningfully delay snapshot collection.
const publicIPTimeout = 3 * time.Second

const ipv4LookupURL = "https://api.ipify.org?format=text"
const ipv6LookupURL = "https://api6.ipify.org?format=text"

// CollectPublicIPs makes a strictly best-effort attempt to determine the
// host's own public IPv4 and IPv6 addresses by asking a well-known external
// service (ipify), using family-pinned endpoints so there is no ambiguity
// about which address family came back. It is the agent's only third-party
// network call.
//
// Either or both may legitimately be empty (no route for that family, DNS
// failure, timeout, service down, malformed response) — that is expected,
// normal, best-effort behavior, never an error condition. This function
// never returns an error and must never be allowed to block or fail the
// rest of snapshot collection.
func CollectPublicIPs(ctx context.Context) (ipv4, ipv6 string) {
	type result struct {
		idx int
		ip  string
	}
	results := make(chan result, 2)

	go func() { results <- result{0, lookupPublicIP(ctx, ipv4LookupURL, isIPv4)} }()
	go func() { results <- result{1, lookupPublicIP(ctx, ipv6LookupURL, isIPv6)} }()

	for i := 0; i < 2; i++ {
		r := <-results
		switch r.idx {
		case 0:
			ipv4 = r.ip
		case 1:
			ipv6 = r.ip
		}
	}
	return ipv4, ipv6
}

// lookupPublicIP fetches url and returns the parsed IP if, and only if, it
// is valid and matches the expected family. Any failure at any stage
// (timeout, DNS, non-200, malformed body, wrong family) yields "" — logged
// at most at debug level, never propagated as an error.
func lookupPublicIP(ctx context.Context, url string, family func(net.IP) bool) string {
	reqCtx, cancel := context.WithTimeout(ctx, publicIPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		log.Printf("debug: public ip lookup %s: build request: %v", url, err)
		return ""
	}

	client := &http.Client{Timeout: publicIPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("debug: public ip lookup %s: %v", url, err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("debug: public ip lookup %s: unexpected status %d", url, resp.StatusCode)
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		log.Printf("debug: public ip lookup %s: read body: %v", url, err)
		return ""
	}

	addr := net.ParseIP(strings.TrimSpace(string(body)))
	if addr == nil || !family(addr) {
		log.Printf("debug: public ip lookup %s: invalid or unexpected-family response", url)
		return ""
	}
	return addr.String()
}

func isIPv4(ip net.IP) bool { return ip.To4() != nil }
func isIPv6(ip net.IP) bool { return ip.To4() == nil && ip.To16() != nil }
