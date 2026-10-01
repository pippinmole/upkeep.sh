package email

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/netguard"
	"github.com/pippinmole/upkeep.sh/server/internal/notify"
	"github.com/pippinmole/upkeep.sh/server/internal/reports"
)

// fixture is the shared report snapshot fixture (web/src/lib).
func fixture(t *testing.T) (*reports.Snapshot, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../../../../web/src/lib/report-snapshot.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var s reports.Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	return &s, raw
}

func reportNote(s *reports.Snapshot, url string) notify.Notification {
	return notify.Notification{
		Version: notify.PayloadVersion, ID: "n-r", DeliveryID: "d-report", Kind: notify.KindReport,
		Summary: reports.Title(*s), Events: []notify.Event{},
		Report: &notify.Report{ID: "r-1", URL: url, Snapshot: s},
	}
}

// Without a renderer, a report email is the plain-text headline with the
// report link.
func TestRenderReportPlainText(t *testing.T) {
	s, _ := fixture(t)
	m := Render(reportNote(s, "https://upkeep.example/dashboard/reports/r-1"))
	// Same subject as web/src/lib/report-summary.ts reportEmailSubject.
	if SubjectPrefix+m.Subject != "[upkeep.sh] Monday patch list: 1 urgent action, 2 to patch this week, 1 image to update, 1 host not reporting" {
		t.Errorf("subject %q", m.Subject)
	}
	for _, want := range []string{"Open findings: 42 (+12, +40%)", "Open in upkeep.sh: https://upkeep.example/dashboard/reports/r-1", "under Reports in the dashboard"} {
		if !strings.Contains(m.Body, want) {
			t.Errorf("body lacks %q:\n%s", want, m.Body)
		}
	}
}

// renderServer is a fake of web's render route: it records the request
// and answers with handle.
type renderServer struct {
	*httptest.Server
	calls atomic.Int32
	auth  atomic.Value // string
	body  atomic.Value // []byte
}

func newRenderServer(t *testing.T, handle http.HandlerFunc) *renderServer {
	t.Helper()
	rs := &renderServer{}
	rs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != RenderPath || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("request %s %s (%s)", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
		}
		rs.auth.Store(r.Header.Get("Authorization"))
		b, _ := io.ReadAll(r.Body)
		rs.body.Store(b)
		handle(w, r)
	}))
	t.Cleanup(rs.Close)
	return rs
}

func renderOK(subject, html, text string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"subject": subject, "html": html, "text": text})
	}
}

var (
	testSecret = "s3cret-render"
	// Parts with lines a naive encoder would get wrong: long lines,
	// non-ASCII, a leading dot, a "--" line and "=" signs.
	testHTML = "<!DOCTYPE html><html><body style=\"font-family: sans-serif\"><h1>Monday patch list — été</h1>" +
		strings.Repeat("<p>Patch now: xz-utils on web-1</p>", 40) + "\n.\n--\n<a href=\"https://upkeep.example/dashboard/reports/r-1?a=1&b=2\">Open</a></body></html>"
	testText = "Monday patch list — été\n\nPatch now (KEV): 1 (+1)\n.\n--\n= not a soft break\n" +
		strings.Repeat("long line ", 30) + "\nOpen in upkeep.sh: https://upkeep.example/dashboard/reports/r-1\n"
	testSubject = "[upkeep.sh] Monday patch list: 1 urgent action, 2 to patch this week, 1 image to update, 1 host not reporting"
)

func renderNotifier(g *netguard.Guard, url string) *Notifier {
	n := newNotifier(g)
	n.Reports = NewReportRenderer(url, testSecret)
	return n
}

// The report email is multipart/alternative with web's text and HTML.
func TestSendRenderedReport(t *testing.T) {
	snap, rawSnap := fixture(t)
	rs := newRenderServer(t, renderOK(testSubject, testHTML, testText))
	f := newFake(t, nil)
	n := renderNotifier(f.guard(), rs.URL+"/") // trailing slash is trimmed
	if _, err := n.Send(context.Background(), f.cfg(SecurityNone),
		reportNote(snap, "https://upkeep.example/dashboard/reports/r-1")); err != nil {
		t.Fatal(err)
	}

	// The request: bearer secret, the snapshot and the report link.
	if got := rs.auth.Load(); got != "Bearer "+testSecret {
		t.Errorf("authorization %q", got)
	}
	var req struct {
		Snapshot  json.RawMessage `json:"snapshot"`
		ReportURL *string         `json:"report_url"`
	}
	if err := json.Unmarshal(rs.body.Load().([]byte), &req); err != nil {
		t.Fatal(err)
	}
	if req.ReportURL == nil || *req.ReportURL != "https://upkeep.example/dashboard/reports/r-1" {
		t.Errorf("report_url %v", req.ReportURL)
	}
	var sent, want any
	_ = json.Unmarshal(req.Snapshot, &sent)
	_ = json.Unmarshal(rawSnap, &want)
	if a, b := mustJSON(t, sent), mustJSON(t, want); a != b {
		t.Errorf("snapshot sent differs from the stored one:\n%s\n%s", a, b)
	}

	// The message.
	m, err := mailRead(f.last().data)
	if err != nil {
		t.Fatal(err)
	}
	h := m.Header
	subj, _ := (&mime.WordDecoder{}).DecodeHeader(h.Get("Subject"))
	if subj != testSubject {
		t.Errorf("subject %q", subj)
	}
	for k, want := range map[string]string{
		"From": `"upkeep.sh" <alerts@example.com>`, "Message-Id": "<d-report@example.com>", "Mime-Version": "1.0",
		"Auto-Submitted": "auto-generated", "X-Upkeep-Kind": "report", "X-Upkeep-Delivery": "d-report",
		"Content-Transfer-Encoding": "",
	} {
		if got := h.Get(k); got != want {
			t.Errorf("%s: %q, want %q", k, got, want)
		}
	}
	mt, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" || !strings.HasPrefix(params["boundary"], "=_upkeep_") {
		t.Fatalf("content type %q: %v", h.Get("Content-Type"), err)
	}
	mr := multipart.NewReader(m.Body, params["boundary"])
	for i, want := range []struct{ ct, body string }{
		{"text/plain; charset=utf-8", testText},
		{"text/html; charset=utf-8", testHTML},
	} {
		p, err := mr.NextPart() // decodes quoted-printable
		if err != nil {
			t.Fatalf("part %d: %v", i, err)
		}
		if got := p.Header.Get("Content-Type"); got != want.ct {
			t.Errorf("part %d content type %q", i, got)
		}
		b, err := io.ReadAll(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.ReplaceAll(string(b), "\r\n", "\n"); got != want.body {
			t.Errorf("part %d body:\n%q\nwant\n%q", i, got, want.body)
		}
	}
	if _, err := mr.NextPart(); err != io.EOF {
		t.Fatalf("more than two parts: %v", err)
	}
}

// mailRead parses a received message without decoding its body.
func mailRead(data string) (*mail.Message, error) { return mail.ReadMessage(strings.NewReader(data)) }

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Without SW_DASHBOARD_URL there is no report link: report_url is null.
func TestRenderReportURLNull(t *testing.T) {
	snap, _ := fixture(t)
	rs := newRenderServer(t, renderOK(testSubject, testHTML, testText))
	if _, err := NewReportRenderer(rs.URL, testSecret).Render(context.Background(), snap, ""); err != nil {
		t.Fatal(err)
	}
	var req map[string]json.RawMessage
	if err := json.Unmarshal(rs.body.Load().([]byte), &req); err != nil {
		t.Fatal(err)
	}
	if string(req["report_url"]) != "null" || len(req["snapshot"]) < 100 {
		t.Fatalf("request %s", rs.body.Load())
	}
}

// Web's subject is sanitized like any other and keeps the prefix.
func TestRenderedSubject(t *testing.T) {
	snap, _ := fixture(t)
	for in, want := range map[string]string{
		"[upkeep.sh] Weekly\r\nBcc: victim@example.net\r\n\r\nbody": "[upkeep.sh] Weekly Bcc: victim@example.net body",
		"Weekly: all clear":                       "[upkeep.sh] Weekly: all clear",
		"  [upkeep.sh]   Weekly:\tall   clear ":   "[upkeep.sh] Weekly: all clear",
		"[upkeep.sh] " + strings.Repeat("é", 150): "[upkeep.sh] " + strings.Repeat("é", 98) + "…",
	} {
		rs := newRenderServer(t, renderOK(in, testHTML, testText))
		r, err := NewReportRenderer(rs.URL, testSecret).Render(context.Background(), snap, "")
		if err != nil {
			t.Fatal(err)
		}
		if r.Subject != want {
			t.Errorf("subject %q -> %q, want %q", in, r.Subject, want)
		}
	}

	// And end to end: no injected header.
	rs := newRenderServer(t, renderOK("[upkeep.sh] Weekly\r\nBcc: victim@example.net", testHTML, testText))
	f := newFake(t, nil)
	if _, err := renderNotifier(f.guard(), rs.URL).Send(context.Background(), f.cfg(SecurityNone), reportNote(snap, "")); err != nil {
		t.Fatal(err)
	}
	m, err := mailRead(f.last().data)
	if err != nil {
		t.Fatal(err)
	}
	if m.Header.Get("Bcc") != "" || len(f.last().rcpt) != 2 {
		t.Fatalf("injected header: %v", m.Header)
	}
}

// A failed render is retried (never permanent) and nothing is sent.
func TestRenderFailuresAreRetried(t *testing.T) {
	snap, _ := fixture(t)
	status := func(code int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { http.Error(w, body, code) }
	}
	raw := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }
	}
	for name, tc := range map[string]struct {
		handle http.HandlerFunc
		want   string
	}{
		"503":           {status(503, "Service Unavailable"), "render report email: web returned 503: Service Unavailable"},
		"500":           {status(500, "Internal Server Error: render failed"), "web returned 500: Internal Server Error: render failed"},
		"401":           {status(401, "Unauthorized"), "web returned 401: Unauthorized"},
		"404":           {status(404, "Not Found"), "web returned 404: Not Found"},
		"400":           {status(400, "Bad Request: body is not JSON"), "web returned 400: Bad Request"},
		"long error":    {status(502, strings.Repeat("x", 5000)), "web returned 502: " + strings.Repeat("x", 290)},
		"invalid JSON":  {raw("<html>not json</html>"), "not the expected JSON"},
		"missing html":  {raw(`{"subject":"s","text":"t"}`), "lacks subject, html or text"},
		"empty subject": {renderOK(" \r\n", testHTML, testText), "empty subject"},
		"prefix only":   {renderOK("[upkeep.sh] ", testHTML, testText), "empty subject"},
		"empty html":    {renderOK(testSubject, " ", testText), "empty html or text"},
		"empty text":    {renderOK(testSubject, testHTML, ""), "empty html or text"},
		"too large":     {renderOK(testSubject, strings.Repeat("a", MaxRenderBytes), testText), "larger than"},
		"timeout": {func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		}, "web unreachable"},
	} {
		t.Run(name, func(t *testing.T) {
			rs := newRenderServer(t, tc.handle)
			f := newFake(t, nil)
			n := renderNotifier(f.guard(), rs.URL)
			n.Reports.HTTP.Timeout = 200 * time.Millisecond
			_, err := n.Send(context.Background(), f.cfg(SecurityNone), reportNote(snap, ""))
			if err == nil || notify.IsPermanent(err) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v (permanent %v), want retryable containing %q", err, notify.IsPermanent(err), tc.want)
			}
			if len(err.Error()) > 500 {
				t.Errorf("error too long for the delivery log: %d bytes", len(err.Error()))
			}
			if f.count() != 0 {
				t.Fatal("connected to the SMTP server after a failed render")
			}
		})
	}

	// Web down: connection refused.
	rs := newRenderServer(t, renderOK(testSubject, testHTML, testText))
	url := rs.URL
	rs.Close()
	f := newFake(t, nil)
	_, err := renderNotifier(f.guard(), url).Send(context.Background(), f.cfg(SecurityNone), reportNote(snap, ""))
	if err == nil || notify.IsPermanent(err) || !strings.Contains(err.Error(), "web unreachable") {
		t.Fatalf("connection refused: %v", err)
	}
}

// An invalid channel config fails permanently before anything is rendered.
func TestRenderAfterValidation(t *testing.T) {
	snap, _ := fixture(t)
	rs := newRenderServer(t, renderOK(testSubject, testHTML, testText))
	f := newFake(t, nil)
	_, err := renderNotifier(f.guard(), rs.URL).Send(context.Background(), f.cfg(SecurityNone, "to", ""), reportNote(snap, ""))
	if !notify.IsPermanent(err) || rs.calls.Load() != 0 {
		t.Fatalf("err %v, render calls %d", err, rs.calls.Load())
	}
}

func TestNewReportRenderer(t *testing.T) {
	for _, c := range [][2]string{{"", ""}, {"http://web:3000", ""}, {"", "s"}, {"  ", "s"}} {
		if NewReportRenderer(c[0], c[1]) != nil {
			t.Errorf("%q: want nil (not configured)", c)
		}
	}
	if r := NewReportRenderer(" http://web:3000/ ", "s"); r == nil || r.url != "http://web:3000/api/internal/render/report" {
		t.Fatalf("renderer %+v", r)
	}
}

var updateGolden = flag.Bool("update", false, "rewrite testdata/{alert,digest,test}.eml")

// Alert, digest and test emails (and a report without a renderer) are
// byte for byte testdata/*.eml (captured when report emails became HTML;
// alert and digest re-captured for alert rules, migration 0024: `go test
// ./internal/notify/email -run TestPlainEmailsUnchanged -update`), whether
// or not a renderer is configured; the renderer is never called for them.
func TestPlainEmailsUnchanged(t *testing.T) {
	snap, _ := fixture(t)
	rs := newRenderServer(t, renderOK(testSubject, testHTML, testText))
	dig := alert(finding(notify.EventAlertFiring, "high", true), notSeen(notify.EventAlertFiring))
	dig.Kind, dig.Summary = notify.KindDigest, "2 events for Critical"
	test := notify.Notification{Version: 1, ID: "n-t", DeliveryID: "d-test", Kind: notify.KindTest, Summary: "Test notification from upkeep.sh"}
	cases := map[string]notify.Notification{
		"alert": alert(finding(notify.EventAlertFiring, "high", true)), "digest": dig, "test": test,
	}
	f := newFake(t, nil)
	if *updateGolden {
		s := settings{from: "alerts@example.com", to: []string{"ops@example.com", "oncall@example.org"}}
		for name, note := range cases {
			msg, err := newNotifier(&netguard.Guard{}).buildMessage(s, note, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile("testdata/"+name+".eml", msg, 0o644); err != nil { //nolint:gosec // committed file, stays world-readable
				t.Fatal(err)
			}
		}
	}
	for name, note := range cases {
		golden, err := os.ReadFile("testdata/" + name + ".eml")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := renderNotifier(f.guard(), rs.URL).Send(context.Background(), f.cfg(SecurityNone), note); err != nil {
			t.Fatal(err)
		}
		// The fake's DATA reader turns CRLF into LF.
		if got, want := f.last().data, strings.ReplaceAll(string(golden), "\r\n", "\n"); got != want {
			t.Errorf("%s email changed:\n%s\nwant\n%s", name, got, want)
		}
	}
	if rs.calls.Load() != 0 {
		t.Fatalf("renderer called %d times for non-report emails", rs.calls.Load())
	}

	// Not configured: the plain-text report, and the exact bytes (CRLF).
	golden, err := os.ReadFile("testdata/report-plain.eml")
	if err != nil {
		t.Fatal(err)
	}
	s := settings{from: "alerts@example.com", to: []string{"ops@example.com", "oncall@example.org"}}
	note := reportNote(snap, "https://upkeep.example/dashboard/reports/r-1")
	msg, err := newNotifier(&netguard.Guard{}).buildMessage(s, note, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, golden) {
		t.Errorf("plain-text report changed:\n%s", msg)
	}
	if _, err := newNotifier(f.guard()).Send(context.Background(), f.cfg(SecurityNone), note); err != nil {
		t.Fatal(err)
	}
	if got := f.last().data; got != strings.ReplaceAll(string(golden), "\r\n", "\n") {
		t.Errorf("sent plain-text report differs:\n%s", got)
	}
	for name := range cases {
		golden, _ := os.ReadFile("testdata/" + name + ".eml")
		msg, err := newNotifier(&netguard.Guard{}).buildMessage(s, cases[name], nil)
		if err != nil || !bytes.Equal(msg, golden) {
			t.Errorf("%s: bytes differ from testdata (%v)", name, err)
		}
	}
}

// The boundary is random per message and absent from both parts.
func TestMultipartBoundary(t *testing.T) {
	a, ba, err := multipartBody(testText, testHTML)
	if err != nil {
		t.Fatal(err)
	}
	_, bb, _ := multipartBody(testText, testHTML)
	if ba == bb || len(ba) != len("=_upkeep_")+32 {
		t.Fatalf("boundaries %q %q", ba, bb)
	}
	if strings.Count(a, ba) != 3 || !strings.HasSuffix(a, "--"+ba+"--\r\n") {
		t.Fatalf("body:\n%s", a)
	}
}
