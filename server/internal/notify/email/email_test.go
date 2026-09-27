package email

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/netip"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/netguard"
	"github.com/pippinmole/upkeep.sh/server/internal/notify"
)

// ---- A small in-process SMTP server ----

// testCert borrows httptest's self-signed certificate (valid for 127.0.0.1
// and example.com) and a pool trusting it.
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv.TLS.Certificates[0], pool
}

type session struct {
	helo     string
	tls      bool // TLS was in place when the message (or AUTH) arrived
	authMech string
	authUser string
	authPass string
	authTLS  bool
	from     string
	rcpt     []string
	data     string
}

type fakeSMTP struct {
	t           *testing.T
	ln          net.Listener
	cert        tls.Certificate
	pool        *x509.CertPool
	implicitTLS bool
	starttls    bool              // advertise STARTTLS
	auth        string            // AUTH mechanisms to advertise ("" = no AUTH)
	user, pass  string            // accepted credentials
	replies     map[string]string // verb (GREET, MAIL, RCPT, DATA, END, AUTH) -> reply override
	silent      bool              // accept but never greet

	mu       sync.Mutex
	sessions []*session
}

func newFake(t *testing.T, opts func(*fakeSMTP)) *fakeSMTP {
	t.Helper()
	cert, pool := testCert(t)
	f := &fakeSMTP{t: t, cert: cert, pool: pool, replies: map[string]string{}}
	if opts != nil {
		opts(f)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.ln = ln
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) port() string { return strconv.Itoa(f.ln.Addr().(*net.TCPAddr).Port) }

// guard reaches the loopback fake (escape hatch) and trusts its cert.
func (f *fakeSMTP) guard() *netguard.Guard {
	return &netguard.Guard{AllowPrivate: true, TLSConfig: &tls.Config{RootCAs: f.pool}}
}

func (f *fakeSMTP) last() session {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sessions) == 0 {
		f.t.Fatal("no SMTP session")
	}
	return *f.sessions[len(f.sessions)-1]
}

func (f *fakeSMTP) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sessions)
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer func() { c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	srvTLS := &tls.Config{Certificates: []tls.Certificate{f.cert}}
	sess := &session{}
	f.mu.Lock()
	f.sessions = append(f.sessions, sess)
	f.mu.Unlock()
	set := func(fn func()) { f.mu.Lock(); fn(); f.mu.Unlock() }
	isTLS := false
	if f.implicitTLS {
		tc := tls.Server(c, srvTLS)
		if tc.Handshake() != nil {
			return
		}
		c, isTLS = tc, true
	}
	if f.silent {
		_, _ = io.Copy(io.Discard, c)
		return
	}
	tp := textproto.NewConn(c)
	reply := func(key, def string) string {
		if r, ok := f.replies[key]; ok {
			return r
		}
		return def
	}
	greet := reply("GREET", "220 fake.test ESMTP")
	_ = tp.PrintfLine("%s", greet)
	if !strings.HasPrefix(greet, "2") {
		return
	}
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO", "HELO":
			set(func() { sess.helo = arg })
			ext := []string{"fake.test", "8BITMIME"}
			if f.starttls && !isTLS {
				ext = append(ext, "STARTTLS")
			}
			if f.auth != "" {
				ext = append(ext, "AUTH "+f.auth)
			}
			for i, e := range ext {
				sep := "-"
				if i == len(ext)-1 {
					sep = " "
				}
				_ = tp.PrintfLine("250%s%s", sep, e)
			}
		case "STARTTLS":
			_ = tp.PrintfLine("220 2.0.0 ready")
			tc := tls.Server(c, srvTLS)
			if tc.Handshake() != nil {
				return
			}
			c, isTLS = tc, true
			tp = textproto.NewConn(c)
		case "AUTH":
			if r, ok := f.replies["AUTH"]; ok {
				_ = tp.PrintfLine("%s", r)
				continue
			}
			mech, ir, _ := strings.Cut(arg, " ")
			var user, pass string
			switch strings.ToUpper(mech) {
			case "PLAIN":
				if ir == "" {
					_ = tp.PrintfLine("334 ")
					if ir, err = tp.ReadLine(); err != nil {
						return
					}
				}
				b, _ := base64.StdEncoding.DecodeString(ir)
				parts := strings.Split(string(b), "\x00")
				if len(parts) == 3 {
					user, pass = parts[1], parts[2]
				}
			case "LOGIN":
				_ = tp.PrintfLine("334 %s", base64.StdEncoding.EncodeToString([]byte("Username:")))
				l, _ := tp.ReadLine()
				u, _ := base64.StdEncoding.DecodeString(l)
				_ = tp.PrintfLine("334 %s", base64.StdEncoding.EncodeToString([]byte("Password:")))
				l, _ = tp.ReadLine()
				p, _ := base64.StdEncoding.DecodeString(l)
				user, pass = string(u), string(p)
			default:
				_ = tp.PrintfLine("504 5.5.4 unrecognized mechanism")
				continue
			}
			set(func() { sess.authMech, sess.authUser, sess.authPass, sess.authTLS = mech, user, pass, isTLS })
			if user == f.user && pass == f.pass {
				_ = tp.PrintfLine("235 2.7.0 authenticated")
			} else {
				_ = tp.PrintfLine("535 5.7.8 authentication credentials invalid")
			}
		case "MAIL":
			set(func() { sess.from = arg })
			_ = tp.PrintfLine("%s", reply("MAIL", "250 2.1.0 ok"))
		case "RCPT":
			set(func() { sess.rcpt = append(sess.rcpt, arg) })
			_ = tp.PrintfLine("%s", reply("RCPT", "250 2.1.5 ok"))
		case "DATA":
			r := reply("DATA", "354 end with <CRLF>.<CRLF>")
			_ = tp.PrintfLine("%s", r)
			if !strings.HasPrefix(r, "354") {
				continue
			}
			b, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			set(func() { sess.data, sess.tls = string(b), isTLS })
			_ = tp.PrintfLine("%s", reply("END", "250 2.0.0 queued as 42"))
		case "RSET", "NOOP":
			_ = tp.PrintfLine("250 ok")
		case "QUIT":
			_ = tp.PrintfLine("221 bye")
			return
		default:
			_ = tp.PrintfLine("502 5.5.2 unknown command")
		}
	}
}

// ---- Fixtures ----

func ptr[T any](v T) *T { return &v }

func finding(typ, sev string, kev bool) notify.Event {
	return notify.Event{ID: 7, Type: typ, URL: "https://app.example/dashboard/hosts/h1/vulnerabilities?v=CVE-2024-3094",
		Host: &notify.Host{ID: "h1", Hostname: "web-1"},
		Finding: &notify.Finding{ID: "f", VulnKey: "CVE-2024-3094", SourcePackage: "xz-utils",
			Packages: []string{"xz-utils", "liblzma5"}, InstalledVersion: "5.6.0-1",
			FixedVersion: ptr("5.6.1-1"), Severity: sev, KEV: kev, EPSS: ptr(0.853)}}
}

func agentEvent(typ, name string) notify.Event {
	seen := time.Date(2026, 9, 27, 10, 30, 0, 0, time.UTC)
	return notify.Event{ID: 8, Type: typ, URL: "https://app.example/dashboard/agents",
		Agent: &notify.Agent{ID: "a", Name: name, LastSeenAt: &seen,
			Hosts: []notify.Host{{ID: "h1", Hostname: "web-1"}}}}
}

func alert(events ...notify.Event) notify.Notification {
	return notify.Notification{Version: notify.PayloadVersion, ID: "n-1", DeliveryID: "0b7c6c1e-2f0e-4d4e-9a39-5b6f1f0d7e11",
		Kind: notify.KindAlert, CreatedAt: time.Unix(1700000000, 0).UTC(), Rule: &notify.RuleRef{ID: "r-1", Name: "Critical"},
		Summary: "summary line", Events: events}
}

func (f *fakeSMTP) cfg(security string, kv ...string) notify.Config {
	c := notify.Config{"host": "127.0.0.1", "port": f.port(), "security": security,
		"from": "alerts@example.com", "to": "ops@example.com, oncall@example.org"}
	for i := 0; i+1 < len(kv); i += 2 {
		c[kv[i]] = kv[i+1]
	}
	return c
}

var fixedNow = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

func newNotifier(g *netguard.Guard) *Notifier {
	n := New(g)
	n.Now = func() time.Time { return fixedNow }
	return n
}

// parse reads a received message: headers and the decoded body.
func parse(t *testing.T, data string) (*mail.Message, string) {
	t.Helper()
	m, err := mail.ReadMessage(strings.NewReader(data))
	if err != nil {
		t.Fatalf("unparseable message: %v\n%s", err, data)
	}
	b, err := io.ReadAll(quotedprintable.NewReader(m.Body))
	if err != nil {
		t.Fatal(err)
	}
	return m, string(b)
}

// ---- Delivery ----

func TestSendSTARTTLSWithAuth(t *testing.T) {
	f := newFake(t, func(f *fakeSMTP) { f.starttls, f.auth, f.user, f.pass = true, "PLAIN LOGIN", "alerts", "s3cret" })
	n := newNotifier(f.guard())
	_, err := n.Send(context.Background(), f.cfg(SecurityStartTLS, "username", "alerts", "password", "s3cret"),
		alert(finding(notify.EventFindingOpened, "high", true)))
	if err != nil {
		t.Fatal(err)
	}
	s := f.last()
	if !s.tls || !s.authTLS || s.authMech != "PLAIN" || s.authUser != "alerts" || s.authPass != "s3cret" {
		t.Fatalf("session %+v", s)
	}
	if s.helo != "example.com" || s.from != "FROM:<alerts@example.com> BODY=8BITMIME" ||
		strings.Join(s.rcpt, "|") != "TO:<ops@example.com>|TO:<oncall@example.org>" {
		t.Fatalf("envelope helo=%q from=%q rcpt=%q", s.helo, s.from, s.rcpt)
	}

	m, body := parse(t, s.data)
	h := m.Header
	for k, want := range map[string]string{
		"From":                      `"upkeep.sh" <alerts@example.com>`,
		"To":                        "ops@example.com, oncall@example.org",
		"Subject":                   "[upkeep.sh] KEV CVE-2024-3094 opened on web-1",
		"Date":                      "Sun, 27 Sep 2026 12:00:00 +0000",
		"Message-Id":                "<0b7c6c1e-2f0e-4d4e-9a39-5b6f1f0d7e11@example.com>",
		"Mime-Version":              "1.0",
		"Content-Type":              "text/plain; charset=utf-8",
		"Content-Transfer-Encoding": "quoted-printable",
		"Auto-Submitted":            "auto-generated",
		"X-Upkeep-Kind":             "alert",
		"X-Upkeep-Delivery":         "0b7c6c1e-2f0e-4d4e-9a39-5b6f1f0d7e11",
	} {
		if got := h.Get(k); got != want {
			t.Errorf("%s: %q, want %q", k, got, want)
		}
	}
	for _, want := range []string{"KEV CVE-2024-3094 opened on web-1", "Package: xz-utils 5.6.0-1 (liblzma5)",
		"Fix: upgrade to 5.6.1-1", "Severity: high, known exploited (CISA KEV), EPSS 85.3%",
		"Open in upkeep.sh: https://app.example/dashboard/hosts/h1/vulnerabilities?v=CVE-2024-3094", "Rule: Critical"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q:\n%s", want, body)
		}
	}
}

// LOGIN is used when PLAIN isn't offered.
func TestSendAuthLogin(t *testing.T) {
	f := newFake(t, func(f *fakeSMTP) { f.starttls, f.auth, f.user, f.pass = true, "LOGIN", "u", "p w" })
	_, err := newNotifier(f.guard()).Send(context.Background(),
		f.cfg("", "username", "u", "password", "p w"), alert(agentEvent(notify.EventAgentStale, "edge")))
	if err != nil {
		t.Fatal(err)
	}
	if s := f.last(); s.authMech != "LOGIN" || s.authUser != "u" || s.authPass != "p w" || !s.authTLS {
		t.Fatalf("session %+v", s)
	}
}

func TestSendImplicitTLS(t *testing.T) {
	f := newFake(t, func(f *fakeSMTP) { f.implicitTLS, f.auth, f.user, f.pass = true, "PLAIN", "u", "p" })
	_, err := newNotifier(f.guard()).Send(context.Background(),
		f.cfg(SecurityTLS, "username", "u", "password", "p"), alert(finding(notify.EventFindingResolved, "low", false)))
	if err != nil {
		t.Fatal(err)
	}
	s := f.last()
	if !s.tls || !s.authTLS || s.authUser != "u" {
		t.Fatalf("session %+v", s)
	}
	if m, _ := parse(t, s.data); m.Header.Get("Subject") != "[upkeep.sh] CVE-2024-3094 resolved on web-1" {
		t.Fatalf("subject %q", m.Header.Get("Subject"))
	}
}

// Security None without credentials: plain SMTP, no TLS, no AUTH.
func TestSendNoneWithoutAuth(t *testing.T) {
	f := newFake(t, func(f *fakeSMTP) { f.starttls = true }) // offered but not used
	_, err := newNotifier(f.guard()).Send(context.Background(), f.cfg(SecurityNone),
		alert(agentEvent(notify.EventAgentRecovered, "edge")))
	if err != nil {
		t.Fatal(err)
	}
	if s := f.last(); s.tls || s.authMech != "" || s.data == "" {
		t.Fatalf("session %+v", s)
	}
}

// Security None with credentials: refused (at validation and on the
// connection) unless insecure authentication is allowed.
func TestInsecureAuth(t *testing.T) {
	f := newFake(t, func(f *fakeSMTP) { f.auth, f.user, f.pass = "PLAIN LOGIN", "u", "p" })
	n := newNotifier(f.guard())

	off := f.cfg(SecurityNone, "username", "u", "password", "p")
	if err := n.Validate(off); err == nil || !strings.Contains(err.Error(), "Allow insecure authentication") {
		t.Fatalf("validate: %v", err)
	}
	_, err := n.Send(context.Background(), off, alert(finding(notify.EventFindingOpened, "high", false)))
	if !notify.IsPermanent(err) || !strings.Contains(err.Error(), "unencrypted") {
		t.Fatalf("send with insecure auth off: %v", err)
	}
	if f.count() != 0 {
		t.Fatal("connected to the server although the config is invalid")
	}

	off["allow_insecure_auth"] = "false"
	if err := n.Validate(off); err == nil {
		t.Fatal("explicit false must still refuse")
	}

	on := f.cfg(SecurityNone, "username", "u", "password", "p", "allow_insecure_auth", "true")
	if _, err := n.Send(context.Background(), on, alert(finding(notify.EventFindingOpened, "high", false))); err != nil {
		t.Fatal(err)
	}
	if s := f.last(); s.authTLS || s.tls || s.authUser != "u" || s.authPass != "p" || s.data == "" {
		t.Fatalf("session %+v", s)
	}
}

// The runtime check on the live connection: even a config that slipped
// past validation never sends credentials over a connection without TLS.
func TestInsecureAuthRefusedOnLiveConnection(t *testing.T) {
	f := newFake(t, func(f *fakeSMTP) { f.auth, f.user, f.pass = "PLAIN", "u", "p" })
	n := newNotifier(f.guard())
	port, _ := strconv.Atoi(f.port())
	s := settings{host: "127.0.0.1", port: port, security: SecurityNone, username: "u", password: "p",
		from: "a@example.com", to: []string{"b@example.com"}}
	err := n.deliver(context.Background(), s, []byte("Subject: x\r\n\r\nx\r\n"))
	if !notify.IsPermanent(err) || !errors.Is(err, ErrInsecureAuth) {
		t.Fatalf("err %v", err)
	}
	if got := f.last(); got.authMech != "" || got.from != "" {
		t.Fatalf("credentials or mail sent: %+v", got)
	}

	// STARTTLS mode: TLS is in place before AUTH, so insecure-auth off is
	// no obstacle.
	f2 := newFake(t, func(f *fakeSMTP) { f.starttls, f.auth, f.user, f.pass = true, "PLAIN", "u", "p" })
	if _, err := newNotifier(f2.guard()).Send(context.Background(),
		f2.cfg(SecurityStartTLS, "username", "u", "password", "p", "allow_insecure_auth", "false"),
		alert(agentEvent(notify.EventAgentStale, "edge"))); err != nil {
		t.Fatal(err)
	}
	if !f2.last().authTLS {
		t.Fatal("auth before TLS")
	}
}

func TestSendRequiresSTARTTLS(t *testing.T) {
	f := newFake(t, func(f *fakeSMTP) { f.auth, f.user, f.pass = "PLAIN", "u", "p" }) // no STARTTLS
	_, err := newNotifier(f.guard()).Send(context.Background(),
		f.cfg(SecurityStartTLS, "username", "u", "password", "p"), alert(agentEvent(notify.EventAgentStale, "edge")))
	if !notify.IsPermanent(err) || !strings.Contains(err.Error(), "does not offer STARTTLS") {
		t.Fatalf("err %v", err)
	}
	if s := f.last(); s.authMech != "" || s.from != "" {
		t.Fatalf("went on without TLS: %+v", s)
	}
}

// Certificates are verified: a guard that doesn't trust the test CA fails
// permanently, in both TLS modes.
func TestSendVerifiesCertificates(t *testing.T) {
	for _, mode := range []string{SecurityStartTLS, SecurityTLS} {
		f := newFake(t, func(f *fakeSMTP) { f.starttls, f.implicitTLS = true, mode == SecurityTLS })
		_, err := newNotifier(&netguard.Guard{AllowPrivate: true}).Send(context.Background(), f.cfg(mode),
			alert(agentEvent(notify.EventAgentStale, "edge")))
		if !notify.IsPermanent(err) || !strings.Contains(err.Error(), "certificate") {
			t.Errorf("%s: err %v", mode, err)
		}
	}
}

// Header injection: event text is sanitized, config values with CR/LF are
// refused, non-ASCII subjects are RFC 2047 encoded.
func TestHeaderInjection(t *testing.T) {
	f := newFake(t, nil)
	n := newNotifier(f.guard())
	// Host labels go into the subject verbatim.
	evil := finding(notify.EventFindingOpened, "high", false)
	evil.Host.Label = ptr("web\r\nBcc: victim@example.net\r\n\r\nspoofed body")
	if _, err := n.Send(context.Background(), f.cfg(SecurityNone), alert(evil)); err != nil {
		t.Fatal(err)
	}
	s := f.last()
	m, _ := parse(t, s.data)
	if m.Header.Get("Bcc") != "" || len(s.rcpt) != 2 {
		t.Fatalf("injected header: %v rcpt %v", m.Header, s.rcpt)
	}
	subj, _ := (&mime.WordDecoder{}).DecodeHeader(m.Header.Get("Subject"))
	if subj != "[upkeep.sh] High CVE-2024-3094 opened on web Bcc: victim@example.net spoofed body" {
		t.Fatalf("subject %q", subj)
	}

	for name, cfg := range map[string]notify.Config{
		"to CRLF":       f.cfg(SecurityNone, "to", "ops@example.com\r\nBcc: victim@example.net"),
		"to LF":         f.cfg(SecurityNone, "to", "ops@example.com\nvictim@example.net"),
		"from CRLF":     f.cfg(SecurityNone, "from", "alerts@example.com\r\nBcc: victim@example.net"),
		"host CRLF":     f.cfg(SecurityNone, "host", "127.0.0.1\r\nRCPT TO:<x@y>"),
		"username CRLF": f.cfg(SecurityStartTLS, "username", "u\r\nMAIL FROM:<x@y>", "password", "p"),
		"password NUL":  f.cfg(SecurityStartTLS, "username", "u", "password", "p\x00x"),
	} {
		if _, err := n.Send(context.Background(), cfg, alert(evil)); !notify.IsPermanent(err) {
			t.Errorf("%s: want permanent error, got %v", name, err)
		}
	}

	var b strings.Builder
	if err := header(&b, "X-Test", "a\r\nBcc: x"); err == nil {
		t.Fatal("header() accepted CR/LF")
	}

	// Non-ASCII subject: encoded, decodes back.
	e := finding(notify.EventFindingOpened, "high", false)
	e.Host.Hostname = "serveur-été"
	if _, err := n.Send(context.Background(), f.cfg(SecurityNone), alert(e)); err != nil {
		t.Fatal(err)
	}
	m, body := parse(t, f.last().data)
	raw := m.Header.Get("Subject")
	if !strings.HasPrefix(raw, "=?utf-8?q?") {
		t.Fatalf("subject not encoded: %q", raw)
	}
	if got, _ := (&mime.WordDecoder{}).DecodeHeader(raw); got != "[upkeep.sh] High CVE-2024-3094 opened on serveur-été" {
		t.Fatalf("decoded subject %q", got)
	}
	if !strings.Contains(body, "serveur-été") {
		t.Fatalf("body %q", body)
	}
}

// Message-ID falls back to a random id when the delivery id isn't a safe
// token; the kind header is dropped rather than injected.
func TestMessageIDFallback(t *testing.T) {
	n := newNotifier(&netguard.Guard{})
	s := settings{from: "a@example.com", to: []string{"b@example.com"}}
	note := alert(finding(notify.EventFindingOpened, "low", false))
	note.DeliveryID, note.Kind = "x\r\nBcc: y", "alert\r\nBcc: y"
	msg, err := n.buildMessage(s, note)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := parse(t, string(msg))
	if id := m.Header.Get("Message-Id"); !strings.HasSuffix(id, "@example.com>") || len(id) != len("<>@example.com")+32 {
		t.Fatalf("message id %q", id)
	}
	if m.Header.Get("Bcc") != "" || m.Header.Get("X-Upkeep-Kind") != "" || m.Header.Get("X-Upkeep-Delivery") != "" {
		t.Fatalf("headers %v", m.Header)
	}
}

func TestRender(t *testing.T) {
	test := Render(notify.Notification{Kind: notify.KindTest, Summary: "Test notification from upkeep.sh"})
	if test.Subject != "Test notification from upkeep.sh" || !strings.Contains(test.Body, "Your email channel works") ||
		strings.Contains(test.Body, "Open in upkeep.sh") {
		t.Fatalf("test: %+v", test)
	}
	stale := Render(alert(agentEvent(notify.EventAgentStale, "edge")))
	if stale.Subject != `Agent "edge" stopped reporting` || !strings.Contains(stale.Body, "Last seen 2026-09-27 10:30 UTC") ||
		!strings.Contains(stale.Body, "Open in upkeep.sh: https://app.example/dashboard/agents") {
		t.Fatalf("stale: %+v", stale)
	}
	if r := Render(alert(agentEvent(notify.EventAgentRecovered, "edge"))); r.Subject != `Agent "edge" is reporting again` {
		t.Fatalf("recovered: %q", r.Subject)
	}
	if r := Render(alert(finding(notify.EventFindingReopened, "critical", false))); r.Subject != "Critical CVE-2024-3094 reopened on web-1" {
		t.Fatalf("reopened: %q", r.Subject)
	}

	var evs []notify.Event
	for range 55 {
		evs = append(evs, finding(notify.EventFindingOpened, "high", false))
	}
	evs = append(evs, agentEvent(notify.EventAgentStale, "edge"))
	d := alert(evs...)
	d.Kind, d.Summary = notify.KindDigest, "Digest: 55 new findings, 1 agent stale"
	dm := Render(d)
	if dm.Subject != d.Summary || strings.Count(dm.Body, "• ") != maxListed || !strings.Contains(dm.Body, "…and 6 more") ||
		!strings.Contains(dm.Body, "Open in upkeep.sh: https://app.example/dashboard\n") {
		t.Fatalf("digest: %+v", dm)
	}
	one := alert(finding(notify.EventFindingOpened, "high", false))
	one.Kind = notify.KindDigest
	if got := Render(one).Subject; got != "Digest: High CVE-2024-3094 opened on web-1" {
		t.Fatalf("single digest subject %q", got)
	}
	noURL := finding(notify.EventFindingOpened, "low", false)
	noURL.URL = ""
	if b := Render(alert(noURL, noURL)).Body; strings.Contains(b, "Open in upkeep.sh") {
		t.Fatalf("link without URL: %s", b)
	}
	long := finding(notify.EventFindingOpened, "low", false)
	long.Host.Hostname = strings.Repeat("é", 300)
	if s := Render(alert(long)).Subject; len(s) > maxSubject || !strings.HasSuffix(s, "…") {
		t.Fatalf("subject len %d", len(s))
	}
}

// ---- Error classification ----

func TestSendClassifiesReplies(t *testing.T) {
	for name, tc := range map[string]struct {
		opts      func(*fakeSMTP)
		cfg       []string
		permanent bool
		want      string
	}{
		"greeting 421":    {func(f *fakeSMTP) { f.replies["GREET"] = "421 4.3.2 too busy" }, nil, false, "SMTP 421 4.3.2 too busy"},
		"greeting 554":    {func(f *fakeSMTP) { f.replies["GREET"] = "554 5.7.1 go away" }, nil, true, "SMTP 554"},
		"MAIL 451":        {func(f *fakeSMTP) { f.replies["MAIL"] = "451 4.7.1 greylisted, try later" }, nil, false, "greylisted"},
		"MAIL 550":        {func(f *fakeSMTP) { f.replies["MAIL"] = "550 5.7.1 sender rejected" }, nil, true, "MAIL FROM <alerts@example.com>: SMTP 550"},
		"RCPT 452":        {func(f *fakeSMTP) { f.replies["RCPT"] = "452 4.2.2 mailbox full" }, nil, false, "SMTP 452"},
		"RCPT 550":        {func(f *fakeSMTP) { f.replies["RCPT"] = "550 5.1.1 no such user" }, nil, true, "RCPT TO <ops@example.com>: SMTP 550 5.1.1 no such user"},
		"DATA 554":        {func(f *fakeSMTP) { f.replies["DATA"] = "554 5.5.1 no valid recipients" }, nil, true, "DATA: SMTP 554"},
		"end of data 552": {func(f *fakeSMTP) { f.replies["END"] = "552 5.3.4 message too big" }, nil, true, "message rejected: SMTP 552"},
		"end of data 450": {func(f *fakeSMTP) { f.replies["END"] = "450 4.7.0 try again" }, nil, false, "SMTP 450"},
		"auth 535":        {func(f *fakeSMTP) { f.starttls, f.auth, f.user, f.pass = true, "PLAIN", "u", "right" }, []string{"username", "u", "password", "wrong"}, true, "authentication failed: SMTP 535"},
		"auth 454": {func(f *fakeSMTP) {
			f.starttls, f.auth, f.replies["AUTH"] = true, "PLAIN", "454 4.7.0 temporary auth failure"
		}, []string{"username", "u", "password", "p"}, false, "SMTP 454"},
		"no AUTH offered":  {func(f *fakeSMTP) { f.starttls = true }, []string{"username", "u", "password", "p"}, true, "does not offer authentication"},
		"no usable mech":   {func(f *fakeSMTP) { f.starttls, f.auth = true, "CRAM-MD5 XOAUTH2" }, []string{"username", "u", "password", "p"}, true, "no supported login mechanism"},
		"long reply text":  {func(f *fakeSMTP) { f.replies["MAIL"] = "550 " + strings.Repeat("x", 2000) }, nil, true, "SMTP 550 xxx"},
		"multi-line reply": {func(f *fakeSMTP) { f.replies["RCPT"] = "550-5.1.1 first line\r\n550 5.1.1 second line" }, nil, true, "first line 5.1.1 second line"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, func(f *fakeSMTP) {
				f.starttls = true
				if tc.opts != nil {
					tc.opts(f)
				}
			})
			_, err := newNotifier(f.guard()).Send(context.Background(), f.cfg(SecurityStartTLS, tc.cfg...),
				alert(agentEvent(notify.EventAgentStale, "edge")))
			if err == nil {
				t.Fatal("no error")
			}
			if notify.IsPermanent(err) != tc.permanent {
				t.Errorf("permanent = %v, want %v (%v)", notify.IsPermanent(err), tc.permanent, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q lacks %q", err, tc.want)
			}
			if len(err.Error()) > maxReply+120 {
				t.Errorf("error too long (%d)", len(err.Error()))
			}
		})
	}
}

func TestSendTransportErrorsAreRetried(t *testing.T) {
	// Connection refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	n := newNotifier(&netguard.Guard{AllowPrivate: true})
	cfg := notify.Config{"host": "127.0.0.1", "port": port, "security": SecurityNone, "from": "a@example.com", "to": "b@example.com"}
	_, err = n.Send(context.Background(), cfg, alert(agentEvent(notify.EventAgentStale, "edge")))
	if err == nil || notify.IsPermanent(err) {
		t.Fatalf("connection refused: %v", err)
	}

	// Server that never greets: timeout.
	f := newFake(t, func(f *fakeSMTP) { f.silent = true })
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err = newNotifier(f.guard()).Send(ctx, f.cfg(SecurityStartTLS), alert(agentEvent(notify.EventAgentStale, "edge")))
	var ne net.Error
	if err == nil || notify.IsPermanent(err) || !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("silent server: %v", err)
	}

	// TLS mode against a plaintext server: a configuration mistake, permanent.
	plain := newFake(t, nil)
	_, err = newNotifier(plain.guard()).Send(context.Background(), plain.cfg(SecurityTLS),
		alert(agentEvent(notify.EventAgentStale, "edge")))
	if !notify.IsPermanent(err) || !strings.Contains(err.Error(), "did not answer with TLS") {
		t.Fatalf("TLS to plaintext: %v", err)
	}
}

// The strict guard refuses loopback, private and metadata addresses and
// non-SMTP ports before connecting: permanent.
func TestSendBlocksPrivateDestinations(t *testing.T) {
	f := newFake(t, nil)
	g := f.guard()
	g.AllowPrivate = false
	n := newNotifier(g)
	for _, hp := range [][2]string{
		{"127.0.0.1", f.port()}, {"127.0.0.1", "587"}, {"10.0.0.8", "25"}, {"169.254.169.254", "465"},
		{"::1", "587"}, {"smtp.example.com", "2526"}, {"smtp.example.com", "443"},
	} {
		cfg := notify.Config{"host": hp[0], "port": hp[1], "from": "a@example.com", "to": "b@example.com"}
		_, err := n.Send(context.Background(), cfg, alert(agentEvent(notify.EventAgentStale, "edge")))
		if !notify.IsPermanent(err) || !errors.Is(err, netguard.ErrBlocked) {
			t.Errorf("%s:%s: want permanent ErrBlocked, got %v", hp[0], hp[1], err)
		}
	}
	// A name resolving to loopback is refused at dial time.
	g.Lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	_, err := n.Send(context.Background(), notify.Config{"host": "smtp.rebind.test", "from": "a@example.com", "to": "b@example.com"},
		alert(agentEvent(notify.EventAgentStale, "edge")))
	if !notify.IsPermanent(err) || !errors.Is(err, netguard.ErrBlocked) {
		t.Errorf("rebinding name: %v", err)
	}
	if f.count() != 0 {
		t.Fatal("the loopback server was reached")
	}
}

// ---- Validation ----

func TestValidate(t *testing.T) {
	n := New(&netguard.Guard{})
	base := func(kv ...string) notify.Config {
		c := notify.Config{"host": "smtp.example.com", "from": "alerts@example.com", "to": "ops@example.com"}
		for i := 0; i+1 < len(kv); i += 2 {
			c[kv[i]] = kv[i+1]
		}
		return c
	}
	for name, cfg := range map[string]notify.Config{
		"minimal":              base(),
		"all ports":            base("port", "25"),
		"465 tls":              base("port", "465", "security", "tls"),
		"2525":                 base("port", "2525", "security", "starttls"),
		"with auth":            base("username", "u", "password", "p w!"),
		"tls auth":             base("security", "tls", "username", "u", "password", "p"),
		"none no auth":         base("security", "none"),
		"none insecure on":     base("security", "none", "username", "u", "password", "p", "allow_insecure_auth", "true"),
		"insecure off":         base("allow_insecure_auth", "false"),
		"many recipients":      base("to", "a@example.com, b@example.com;c@example.org ,"),
		"ipv6 literal":         base("host", "2606:4700:4700::1111"),
		"bracketed ipv6":       base("host", "[2606:4700:4700::1111]"),
		"public ip":            base("host", "8.8.8.8"),
		"subaddress recipient": base("to", "ops+alerts@example.com"),
	} {
		if err := n.Validate(cfg); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	tooMany := make([]string, MaxRecipients+1)
	for i := range tooMany {
		tooMany[i] = "u" + strconv.Itoa(i) + "@example.com"
	}
	for name, cfg := range map[string]notify.Config{
		"no host":               base("host", ""),
		"no from":               base("from", ""),
		"no to":                 base("to", ""),
		"only commas":           base("to", " , ;"),
		"bad port":              base("port", "abc"),
		"port range":            base("port", "70000"),
		"blocked port":          base("port", "2526"),
		"https port":            base("port", "443"),
		"private host":          base("host", "192.168.1.10"),
		"loopback host":         base("host", "127.0.0.1"),
		"host with port":        base("host", "smtp.example.com:587"),
		"host URL":              base("host", "smtp://smtp.example.com"),
		"bad security":          base("security", "ssl"),
		"bad from":              base("from", "not-an-address"),
		"from display name":     base("from", "Alerts <alerts@example.com>"),
		"bad to":                base("to", "ops@example.com, nope"),
		"to display name":       base("to", `"Ops" <ops@example.com>`),
		"non-ascii to":          base("to", "opé@example.com"),
		"too many recipients":   base("to", strings.Join(tooMany, ",")),
		"username only":         base("username", "u"),
		"password only":         base("password", "p"),
		"none + auth":           base("security", "none", "username", "u", "password", "p"),
		"none + auth + false":   base("security", "none", "username", "u", "password", "p", "allow_insecure_auth", "false"),
		"bad insecure flag":     base("allow_insecure_auth", "yes"),
		"username line break":   base("username", "u\nx", "password", "p"),
		"from injection":        base("from", "a@example.com\r\nBcc: b@example.com"),
		"to injection":          base("to", "a@example.com\r\nBcc: b@example.com"),
		"host injection":        base("host", "smtp.example.com\r\nX: y"),
		"host too long label":   base("host", strings.Repeat("a", 64)+".example.com"),
		"to longer than 2048":   base("to", strings.Repeat("a", 2049)),
		"metadata host literal": base("host", "169.254.169.254"),
	} {
		if err := n.Validate(cfg); err == nil {
			t.Errorf("%s: valid", name)
		}
	}
}

func TestDefaultPorts(t *testing.T) {
	n := New(&netguard.Guard{})
	for mode, want := range map[string]int{"": 587, SecurityStartTLS: 587, SecurityNone: 587, SecurityTLS: 465} {
		s, err := n.parse(notify.Config{"host": "smtp.example.com", "security": mode, "from": "a@example.com", "to": "b@example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if s.port != want {
			t.Errorf("%q: port %d, want %d", mode, s.port, want)
		}
		if mode == "" && s.security != SecurityStartTLS {
			t.Errorf("default security %q", s.security)
		}
	}
}
