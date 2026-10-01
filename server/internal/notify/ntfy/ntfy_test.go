package ntfy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/netguard"
	"github.com/pippinmole/upkeep.sh/server/internal/notify"
)

func tlsGuard(srv *httptest.Server) *netguard.Guard {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &netguard.Guard{AllowPrivate: true, TLSConfig: &tls.Config{RootCAs: pool}}
}

func ptr[T any](v T) *T { return &v }

var fired = time.Date(2026, 9, 27, 11, 0, 0, 0, time.UTC)

// withState sets the alert's state from the event type.
func withState(e notify.Event) notify.Event {
	e.Alert.State, e.Alert.FiredAt = "firing", fired
	if e.Type == notify.EventAlertResolved {
		at := fired.Add(time.Hour)
		e.Alert.State, e.Alert.ResolvedAt = "resolved", &at
	}
	return e
}

// finding is a vulnerability rule's event (alert title as the store's
// evaluator writes it: alerting.VulnTitle).
func finding(typ, sev string, kev bool) notify.Event {
	prefix := strings.ToUpper(sev[:1]) + sev[1:] + " "
	if kev {
		prefix = "KEV "
	}
	return withState(notify.Event{
		ID: 7, Type: typ, URL: "https://app.example/dashboard/hosts/h1/vulnerabilities?v=CVE-2024-3094",
		Alert: &notify.Alert{
			ID: "a1", Property: "vulnerability", Subject: "pkg:xz-utils:CVE-2024-3094",
			Title: prefix + "CVE-2024-3094 in xz-utils",
		},
		Host: &notify.Host{ID: "h1", Hostname: "web-1"},
		Finding: &notify.Finding{
			ID: "f", VulnKey: "CVE-2024-3094", SourcePackage: "xz-utils",
			Packages: []string{"xz-utils", "liblzma5"}, InstalledVersion: "5.6.0-1",
			FixedVersion: ptr("5.6.1-1"), Severity: sev, KEV: kev, EPSS: ptr(0.853),
		},
	})
}

// notSeen is a host_not_seen rule's event.
func notSeen(typ string) notify.Event {
	return withState(notify.Event{
		ID: 8, Type: typ, URL: "https://app.example/dashboard/alerts?host=h2",
		Host: &notify.Host{ID: "h2", Hostname: "db-1", Label: ptr("database")},
		Alert: &notify.Alert{
			ID: "a2", Property: "host_not_seen", Title: "Not seen for more than 30 minutes",
			Details: json.RawMessage(`{"last_seen_at":"2026-09-27T10:30:00Z"}`),
		},
	})
}

// port is a listening_port rule's event.
func port(typ string) notify.Event {
	return withState(notify.Event{
		ID: 9, Type: typ, URL: "https://app.example/dashboard/alerts?host=h1",
		Host: &notify.Host{ID: "h1", Hostname: "web-1"},
		Alert: &notify.Alert{
			ID: "a3", Property: "listening_port", Subject: "tcp/22", Title: "Port 22/tcp is listening",
			Details: json.RawMessage(`{"addresses":["0.0.0.0","::"],"port":22,"processes":["sshd"],"transport":"tcp"}`),
		},
	})
}

func alert(events ...notify.Event) notify.Notification {
	return notify.Notification{
		Version: notify.PayloadVersion, ID: "n-1", DeliveryID: "d-1", Kind: notify.KindAlert,
		CreatedAt: time.Unix(1700000000, 0).UTC(), Rule: &notify.RuleRef{ID: "r-1", Name: "Critical"},
		Summary: "summary line", Events: events,
	}
}

func TestSendPublishesJSON(t *testing.T) {
	var got struct {
		path, method string
		headers      http.Header
		body         []byte
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.path, got.method, got.headers = r.URL.Path, r.Method, r.Header.Clone()
		got.body, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"id":"abc","event":"message"}`))
	}))
	defer srv.Close()

	n := New(tlsGuard(srv))
	cfg := notify.Config{"server": srv.URL + "/", "topic": "upkeep-test_1", "token": "tk_secret"}
	res, err := n.Send(context.Background(), cfg, alert(finding(notify.EventAlertFiring, "high", true)))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK || !strings.Contains(res.Response, `"abc"`) {
		t.Fatalf("result %+v", res)
	}
	if got.method != http.MethodPost || got.path != "/" {
		t.Fatalf("%s %s, want POST /", got.method, got.path)
	}
	h := got.headers
	if h.Get("Authorization") != "Bearer tk_secret" || h.Get("Content-Type") != "application/json" || h.Get("User-Agent") != UserAgent {
		t.Fatalf("headers %v", h)
	}
	var m Message
	if err := json.Unmarshal(got.body, &m); err != nil {
		t.Fatal(err)
	}
	if m.Topic != "upkeep-test_1" || m.Title != "KEV CVE-2024-3094 in xz-utils on web-1" || m.Priority != PriorityUrgent ||
		m.Click != "https://app.example/dashboard/hosts/h1/vulnerabilities?v=CVE-2024-3094" ||
		!slices.Equal(m.Tags, []string{"rotating_light", "kev", "high", "web-1"}) {
		t.Fatalf("message %s", got.body)
	}
	for _, want := range []string{
		"Package: xz-utils 5.6.0-1 (liblzma5)", "Fix: upgrade to 5.6.1-1",
		"Severity: high, known exploited (CISA KEV), EPSS 85.3%", "Rule: Critical",
	} {
		if !strings.Contains(m.Message, want) {
			t.Errorf("message lacks %q:\n%s", want, m.Message)
		}
	}
}

// Self-hosted servers behind a path prefix keep it; no token = no auth.
func TestSendSelfHostedPrefixNoToken(t *testing.T) {
	var path, auth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth = r.URL.Path, r.Header.Get("Authorization")
	}))
	defer srv.Close()
	_, err := New(tlsGuard(srv)).Send(context.Background(),
		notify.Config{"server": srv.URL + "/ntfy", "topic": "alerts"}, alert(notSeen(notify.EventAlertFiring)))
	if err != nil {
		t.Fatal(err)
	}
	if path != "/ntfy/" || auth != "" {
		t.Fatalf("path %q auth %q", path, auth)
	}
}

func TestRenderPriorities(t *testing.T) {
	for name, tc := range map[string]struct {
		n        notify.Notification
		priority string
		want     int
	}{
		"kev medium firing":   {alert(finding(notify.EventAlertFiring, "medium", true)), "", PriorityUrgent},
		"critical firing":     {alert(finding(notify.EventAlertFiring, "critical", false)), "", PriorityUrgent},
		"high opened":         {alert(finding(notify.EventAlertFiring, "high", false)), "", PriorityHigh},
		"medium opened":       {alert(finding(notify.EventAlertFiring, "medium", false)), "auto", PriorityDefault},
		"low opened":          {alert(finding(notify.EventAlertFiring, "low", false)), "", PriorityLow},
		"unknown opened":      {alert(finding(notify.EventAlertFiring, "unknown", false)), "", PriorityLow},
		"kev resolved":        {alert(finding(notify.EventAlertResolved, "critical", true)), "", PriorityLow},
		"host not seen":       {alert(notSeen(notify.EventAlertFiring)), "", PriorityHigh},
		"not seen resolved":   {alert(notSeen(notify.EventAlertResolved)), "", PriorityLow},
		"test":                {notify.Notification{Kind: notify.KindTest, Events: []notify.Event{}}, "", PriorityDefault},
		"fixed override":      {alert(finding(notify.EventAlertFiring, "critical", true)), "2", PriorityLow},
		"batch takes the max": {alert(finding(notify.EventAlertResolved, "low", false), finding(notify.EventAlertFiring, "high", false)), "", PriorityHigh},
		"digest capped": {func() notify.Notification {
			n := alert(finding(notify.EventAlertFiring, "critical", true), notSeen(notify.EventAlertResolved))
			n.Kind = notify.KindDigest
			return n
		}(), "", PriorityHigh},
	} {
		if got := Render("t", tc.priority, tc.n).Priority; got != tc.want {
			t.Errorf("%s: priority %d, want %d", name, got, tc.want)
		}
	}
}

func TestRenderMessages(t *testing.T) {
	stale := Render("t", "", alert(notSeen(notify.EventAlertFiring)))
	if stale.Title != "Not seen for more than 30 minutes on database" || stale.Click != "https://app.example/dashboard/alerts?host=h2" ||
		!strings.Contains(stale.Message, "Last seen: 2026-09-27 10:30 UTC") ||
		!strings.Contains(stale.Message, "Firing since 2026-09-27 11:00 UTC.") || stale.Tags[0] != "electric_plug" {
		t.Fatalf("stale: %+v", stale)
	}
	if r := Render("t", "", alert(notSeen(notify.EventAlertResolved))); r.Title != "Resolved: Not seen for more than 30 minutes on database" ||
		r.Tags[0] != "white_check_mark" || !strings.Contains(r.Message, "Fired 2026-09-27 11:00 UTC, resolved 2026-09-27 12:00 UTC.") {
		t.Fatalf("recovered: %+v", r)
	}
	res := Render("t", "", alert(finding(notify.EventAlertResolved, "critical", true)))
	if res.Title != "Resolved: KEV CVE-2024-3094 in xz-utils on web-1" || !strings.Contains(res.Message, "No longer present") || res.Tags[0] != "white_check_mark" {
		t.Fatalf("resolved: %+v", res)
	}
	if r := Render("t", "", alert(finding(notify.EventAlertFiring, "critical", false))); r.Title != "Critical CVE-2024-3094 in xz-utils on web-1" {
		t.Fatalf("critical: %q", r.Title)
	}
	p := Render("t", "", alert(port(notify.EventAlertFiring)))
	if p.Title != "Port 22/tcp is listening on web-1" || p.Priority != PriorityDefault || p.Tags[0] != "bell" ||
		!strings.Contains(p.Message, "Listening on: 0.0.0.0, ::\nProcess: sshd\nFiring since") {
		t.Fatalf("port: %+v", p)
	}

	test := Render("t", "", notify.Notification{Kind: notify.KindTest, Summary: "Test notification from upkeep.sh", Events: []notify.Event{}})
	if test.Title != "Test notification from upkeep.sh" || test.Message == "" || test.Click != "" {
		t.Fatalf("test: %+v", test)
	}

	// Digest of many events: summary title, bulleted list capped at
	// maxListed, the dashboard root as the link.
	var evs []notify.Event
	for range 12 {
		evs = append(evs, finding(notify.EventAlertFiring, "high", false))
	}
	evs = append(evs, notSeen(notify.EventAlertFiring))
	d := alert(evs...)
	d.Kind, d.Summary = notify.KindDigest, "Digest: 13 firing alerts across 2 hosts"
	dm := Render("t", "", d)
	if dm.Title != d.Summary || dm.Click != "https://app.example/dashboard" ||
		strings.Count(dm.Message, "• ") != maxListed || !strings.Contains(dm.Message, "…and 3 more") {
		t.Fatalf("digest: %+v", dm)
	}
	// Digest of one event still says it's a digest.
	one := alert(finding(notify.EventAlertFiring, "high", false))
	one.Kind = notify.KindDigest
	if got := Render("t", "", one).Title; got != "Digest: High CVE-2024-3094 in xz-utils on web-1" {
		t.Fatalf("single digest title %q", got)
	}
	// Events without links: no click.
	noURL := finding(notify.EventAlertFiring, "low", false)
	noURL.URL = ""
	if c := Render("t", "", alert(noURL, noURL)).Click; c != "" {
		t.Fatalf("click %q", c)
	}
}

func TestRenderStaysUnderNtfyLimit(t *testing.T) {
	e := finding(notify.EventAlertFiring, "high", false)
	e.Finding.SourcePackage = strings.Repeat("é", 3000)
	m := Render("t", "", alert(e))
	if len(m.Message) > maxMessage || !strings.HasSuffix(m.Message, "…") || !strings.Contains(m.Message, "é") {
		t.Fatalf("message len %d", len(m.Message))
	}
	if !json.Valid(must(json.Marshal(m))) {
		t.Fatal("invalid JSON")
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestSendClassifiesResponses(t *testing.T) {
	code := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if code == http.StatusFound {
			w.Header().Set("Location", "https://elsewhere.invalid/")
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"code":40301,"http":403,"error":"forbidden","link":"https://ntfy.sh/docs/publish/#authentication"}`))
	}))
	defer srv.Close()
	n := New(tlsGuard(srv))
	cfg := notify.Config{"server": srv.URL, "topic": "alerts"}
	for c, wantPermanent := range map[int]bool{
		500: false, 502: false, 503: false, 429: false, 408: false,
		400: true, 401: true, 403: true, 404: true, 413: true, 302: true,
	} {
		code = c
		res, err := n.Send(context.Background(), cfg, alert(finding(notify.EventAlertFiring, "high", false)))
		if err == nil {
			t.Errorf("%d: no error", c)
			continue
		}
		if notify.IsPermanent(err) != wantPermanent {
			t.Errorf("%d: permanent = %v, want %v (%v)", c, notify.IsPermanent(err), wantPermanent, err)
		}
		if c != 302 {
			if res.StatusCode != c {
				t.Errorf("%d: status %d", c, res.StatusCode)
			}
			if !strings.Contains(err.Error(), "forbidden (code 40301)") {
				t.Errorf("%d: error lacks ntfy's message: %v", c, err)
			}
		}
	}
}

func TestSendErrorIncludesTruncatedRawBody(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>bad gateway " + strings.Repeat("x", 10000) + "</html>"))
	}))
	defer srv.Close()
	res, err := New(tlsGuard(srv)).Send(context.Background(),
		notify.Config{"server": srv.URL, "topic": "alerts"}, alert(notSeen(notify.EventAlertFiring)))
	if err == nil || notify.IsPermanent(err) || !strings.Contains(err.Error(), "HTTP 502: <html>bad gateway") ||
		len(err.Error()) > maxErrBody+40 {
		t.Fatalf("err %v", err)
	}
	if len(res.Response) > maxResponse || !strings.HasSuffix(res.Response, "…") {
		t.Fatalf("response len %d", len(res.Response))
	}
}

// The strict (production) guard refuses loopback, plain http and ports
// other than 443/8443: permanent, never retried.
func TestSendBlocksPrivateDestinations(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached a loopback server")
	}))
	defer srv.Close()
	g := tlsGuard(srv)
	g.AllowPrivate = false
	n := New(g)
	for _, u := range []string{
		srv.URL, "https://127.0.0.1/", "https://169.254.169.254/", "http://ntfy.example.com/",
		"https://ntfy.example.com:2586/",
	} {
		_, err := n.Send(context.Background(), notify.Config{"server": u, "topic": "alerts"}, alert(notSeen(notify.EventAlertFiring)))
		if !notify.IsPermanent(err) || !errors.Is(err, netguard.ErrBlocked) {
			t.Errorf("%s: want permanent ErrBlocked, got %v", u, err)
		}
	}
}

func TestValidate(t *testing.T) {
	n := New(&netguard.Guard{})
	for name, cfg := range map[string]notify.Config{
		"default server": {"topic": "upkeep-alerts_1"},
		"self-hosted":    {"server": "https://ntfy.example.com", "topic": "a"},
		"port 8443":      {"server": "https://ntfy.example.com:8443/", "topic": "a", "token": "tk_abc", "priority": "4"},
		"auto priority":  {"topic": "a", "priority": "auto"},
		"64 char topic":  {"topic": strings.Repeat("a", 64)},
	} {
		if err := n.Validate(cfg); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, cfg := range map[string]notify.Config{
		"no topic":       {},
		"topic slash":    {"topic": "a/b"},
		"topic space":    {"topic": "a b"},
		"topic dot":      {"topic": "a.b"},
		"topic unicode":  {"topic": "alerté"},
		"topic too long": {"topic": strings.Repeat("a", 65)},
		"http":           {"server": "http://ntfy.example.com", "topic": "a"},
		"private":        {"server": "https://10.1.2.3", "topic": "a"},
		"port":           {"server": "https://ntfy.example.com:2586", "topic": "a"},
		"query":          {"server": "https://ntfy.example.com/?x=1", "topic": "a"},
		"bad priority":   {"topic": "a", "priority": "6"},
		"token newline":  {"topic": "a", "token": "tk_a\r\nX-Evil: 1"}, //nolint:gosec // test fixture, not a credential
		"token space":    {"topic": "a", "token": "tk a"},
	} {
		if err := n.Validate(cfg); err == nil {
			t.Errorf("%s: valid", name)
		}
	}
}
