package netguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCheckAddr(t *testing.T) {
	blockedAddrs := []string{
		"127.0.0.1", "127.8.9.10", "::1",
		"10.0.0.1", "172.16.5.4", "172.31.255.255", "192.168.1.1",
		"169.254.169.254", // cloud metadata
		"169.254.0.1", "fe80::1",
		"100.64.0.1", "100.100.100.200", // CGNAT, Alibaba metadata
		"0.0.0.0", "0.1.2.3", "::",
		"224.0.0.1", "239.255.255.250", "ff02::1", "ff05::2",
		"255.255.255.255", "240.0.0.1",
		"192.0.2.1", "198.51.100.7", "203.0.113.9", "198.18.0.1", "192.0.0.8",
		"fc00::1", "fd00:ec2::254", // ULA, AWS IPv6 metadata
		"fec0::1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", // IPv4-mapped
		"64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", // NAT64 of loopback / metadata
		"2002:7f00:1::1",     // 6to4 of 127.0.0.1
		"2001:0:4136:e378::", // Teredo
		"2001:db8::1",
	}
	for _, s := range blockedAddrs {
		if err := CheckAddr(netip.MustParseAddr(s)); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: want blocked, got %v", s, err)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "2a00:1450:4009:81f::200e"} {
		if err := CheckAddr(netip.MustParseAddr(s)); err != nil {
			t.Errorf("%s: want allowed, got %v", s, err)
		}
	}
}

func TestCheckURL(t *testing.T) {
	g := &Guard{}
	for _, bad := range []string{
		"http://example.com/hook",         // plain http
		"ftp://example.com/",              // scheme
		"https://user:pw@example.com/",    // userinfo
		"https://example.com:22/",         // port
		"https://example.com:8080/",       // port
		"https://127.0.0.1/",              // literal loopback
		"https://[::1]/",                  // literal loopback v6
		"https://169.254.169.254/latest/", // metadata
		"https://[::ffff:10.0.0.1]/",      // mapped private
		"https:///nohost",                 // no host
		"not a url at all\x7f",            // unparseable
	} {
		if _, err := g.CheckURL(bad); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
	for _, ok := range []string{"https://example.com/hook", "https://example.com:443/x?y=1", "https://example.com:8443/", "https://8.8.8.8/"} {
		if _, err := g.CheckURL(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	dev := &Guard{AllowPrivate: true}
	for _, ok := range []string{"http://localhost:9000/hook", "https://127.0.0.1:1234/", "http://10.0.0.5/"} {
		if _, err := dev.CheckURL(ok); err != nil {
			t.Errorf("escape hatch %q: %v", ok, err)
		}
	}
	if _, err := dev.CheckURL("ftp://x/"); err == nil {
		t.Error("escape hatch must still refuse non-http schemes")
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv(EnvAllowPrivate, "")
	if FromEnv().AllowPrivate {
		t.Fatal("escape hatch must be off by default")
	}
	t.Setenv(EnvAllowPrivate, "true")
	if !FromEnv().AllowPrivate {
		t.Fatal("escape hatch not read")
	}
}

func lookupTable(m map[string][]string) func(context.Context, string) ([]netip.Addr, error) {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, s := range m[host] {
			out = append(out, netip.MustParseAddr(s))
		}
		if len(out) == 0 {
			return nil, errors.New("no such host")
		}
		return out, nil
	}
}

func TestResolveRefusesAnyBlockedAnswer(t *testing.T) {
	g := &Guard{Lookup: lookupTable(map[string][]string{
		"public.test":  {"93.184.216.34"},
		"mixed.test":   {"93.184.216.34", "10.0.0.7"},
		"private.test": {"192.168.0.10"},
		"meta.test":    {"169.254.169.254"},
		"mapped.test":  {"::ffff:127.0.0.1"},
	})}
	ctx := context.Background()
	if _, err := g.Resolve(ctx, "public.test"); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"mixed.test", "private.test", "meta.test", "mapped.test"} {
		if _, err := g.Resolve(ctx, h); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: want blocked, got %v", h, err)
		}
	}
}

// DNS rebinding: the name resolves to a public address when validated and
// to loopback when the request is made. The request must be refused: the
// check runs on the address actually dialed.
func TestDNSRebindingIsBlockedAtDialTime(t *testing.T) {
	var calls atomic.Int32
	g := &Guard{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		if calls.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}}
	if _, err := g.CheckURL("https://rebind.test/hook"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Resolve(context.Background(), "rebind.test"); err != nil {
		t.Fatalf("validation lookup: %v", err)
	}
	_, err := g.Client(2*time.Second).Post("https://rebind.test/hook", "application/json", strings.NewReader("{}"))
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("rebinding to loopback not blocked: %v", err)
	}
}

// A real listener on loopback is unreachable with the strict guard, and
// reachable through the dev escape hatch.
func TestLoopbackServerBlockedUnlessEscapeHatch(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()

	strict := &Guard{AllowedPorts: []int{portOf(t, srv.URL)}} // port allowed, address not
	// Scheme check aside (httptest is http), go straight to the dialer.
	if _, err := strict.DialContext(context.Background(), "tcp", strings.TrimPrefix(srv.URL, "http://")); !errors.Is(err, ErrBlocked) {
		t.Fatalf("strict dial to loopback: %v", err)
	}
	// "localhost" resolved by the real resolver is blocked too.
	if _, err := strict.DialContext(context.Background(), "tcp", net.JoinHostPort("localhost", "443")); !errors.Is(err, ErrBlocked) {
		t.Fatalf("strict dial to localhost: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("server was reached")
	}

	dev := &Guard{AllowPrivate: true}
	resp, err := dev.Client(2 * time.Second).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hits.Load() != 1 {
		t.Fatal("escape hatch did not reach the server")
	}
}

func TestRedirects(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("cross-origin redirect was followed")
	}))
	defer other.Close()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cross":
			http.Redirect(w, r, other.URL+"/x", http.StatusTemporaryRedirect)
		case "/metadata":
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
		case "/same":
			http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusTemporaryRedirect)
		case "/final":
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	// The escape hatch is needed to reach httptest at all; the origin rule
	// holds regardless.
	c := (&Guard{AllowPrivate: true}).Client(2 * time.Second)
	for _, p := range []string{"/cross", "/metadata", "/loop"} {
		if _, err := c.Post(srv.URL+p, "application/json", strings.NewReader("{}")); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: want blocked, got %v", p, err)
		}
	}
	resp, err := c.Post(srv.URL+"/same", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("same-origin redirect: %d", resp.StatusCode)
	}

	// With the strict guard a redirect to metadata fails the scheme/address
	// check even when it keeps the origin's host shape.
	strict := (&Guard{Lookup: lookupTable(map[string][]string{"hook.test": {"93.184.216.34"}})}).Client(time.Second)
	req, _ := http.NewRequest(http.MethodGet, "https://hook.test/", nil)
	if err := strict.CheckRedirect(mustReq(t, "https://169.254.169.254/"), []*http.Request{req}); !errors.Is(err, ErrBlocked) {
		t.Errorf("redirect to metadata: %v", err)
	}
}

func mustReq(t *testing.T, u string) *http.Request {
	r, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func portOf(t *testing.T, u string) int {
	_, p, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(u, "http://"), "https://"))
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for _, c := range p {
		n = n*10 + int(c-'0')
	}
	return n
}

func TestCheckSMTP(t *testing.T) {
	g := &Guard{}
	for _, port := range SMTPPorts {
		if err := g.CheckSMTP("smtp.example.com", port); err != nil {
			t.Errorf("port %d: %v", port, err)
		}
	}
	for _, ok := range []string{"mail.example.com.", "8.8.8.8", "2606:4700:4700::1111", "[2606:4700:4700::1111]", "smtp_relay.example.com"} {
		if err := g.CheckSMTP(ok, 587); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, port := range []int{22, 80, 443, 8443, 2586, 1025, 110, 143, 993} {
		if err := g.CheckSMTP("smtp.example.com", port); !errors.Is(err, ErrBlocked) {
			t.Errorf("port %d: want blocked, got %v", port, err)
		}
	}
	for _, bad := range []string{"127.0.0.1", "::1", "[::1]", "10.1.2.3", "192.168.0.1", "169.254.169.254", "::ffff:10.0.0.1"} {
		if err := g.CheckSMTP(bad, 587); !errors.Is(err, ErrBlocked) {
			t.Errorf("%q: want blocked, got %v", bad, err)
		}
	}
	for _, bad := range []string{"", "smtp.example.com:587", "smtp://smtp.example.com", "mail example.com",
		"mail.example.com\r\nRCPT TO:<x@y>", "-bad.example.com", "a..b", "user@mail.example.com", "mail.example.com/x"} {
		if err := g.CheckSMTP(bad, 587); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
	for _, port := range []int{0, -1, 65536} {
		if err := g.CheckSMTP("smtp.example.com", port); err == nil {
			t.Errorf("port %d: want error", port)
		}
	}
	// The HTTP policy is untouched: SMTP ports stay closed to https.
	if _, err := g.CheckURL("https://example.com:587/"); !errors.Is(err, ErrBlocked) {
		t.Errorf("https on an SMTP port: %v", err)
	}

	dev := &Guard{AllowPrivate: true}
	for _, ok := range []struct {
		host string
		port int
	}{{"127.0.0.1", 1025}, {"localhost", 25}, {"10.0.0.5", 587}, {"[::1]", 2525}} {
		if err := dev.CheckSMTP(ok.host, ok.port); err != nil {
			t.Errorf("escape hatch %s:%d: %v", ok.host, ok.port, err)
		}
	}
	if err := dev.CheckSMTP("bad host", 25); err == nil {
		t.Error("escape hatch must still refuse malformed hosts")
	}
}

// DialSMTP checks the resolved address at dial time: a name resolving to
// loopback or a private address is refused, a real loopback listener is
// only reachable through the escape hatch.
func TestDialSMTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var hits atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	strict := &Guard{Lookup: lookupTable(map[string][]string{
		"loop.test":  {"127.0.0.1"},
		"priv.test":  {"10.0.0.7"},
		"mixed.test": {"93.184.216.34", "192.168.1.1"},
		"meta.test":  {"169.254.169.254"},
		"localhost":  {"127.0.0.1", "::1"},
	})}
	ctx := context.Background()
	for _, h := range []string{"loop.test", "priv.test", "mixed.test", "meta.test", "127.0.0.1", "localhost"} {
		if _, err := strict.DialSMTP(ctx, h, 587); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: want blocked, got %v", h, err)
		}
	}
	if _, err := strict.DialSMTP(ctx, "127.0.0.1", port); !errors.Is(err, ErrBlocked) {
		t.Errorf("strict dial to the loopback listener: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("listener was reached by the strict guard")
	}

	c, err := (&Guard{AllowPrivate: true}).DialSMTP(ctx, "127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	deadline := time.Now().Add(2 * time.Second)
	for hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hits.Load() != 1 {
		t.Fatal("escape hatch did not reach the listener")
	}
}
