package webhook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/netguard"
	"github.com/pippinmole/upkeep.sh/server/internal/notify"
)

// Reference vector computed independently:
//
//	printf '1700000000.{"hello":"world"}' | openssl dgst -sha256 -hmac whsec_test
func TestSignVector(t *testing.T) {
	got := Sign("whsec_test", 1700000000, []byte(`{"hello":"world"}`))
	want := "v1=f592bbf3951cfc94e560eecfb5d9dd4da6b0fff2e626235f8ab4b54860925d0b"
	if got != want {
		t.Fatalf("Sign = %s, want %s", got, want)
	}
}

func TestVerify(t *testing.T) {
	body := []byte(`{"a":1}`)
	now := time.Unix(1700000000, 0)
	sig := Sign("s3cret", now.Unix(), body)
	ok := func(secret, sig, ts string, body []byte, at time.Time) error {
		return Verify(secret, sig, ts, body, at, 5*time.Minute)
	}
	if err := ok("s3cret", sig, "1700000000", body, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Several signatures (secret rotation) — any may match.
	if err := ok("s3cret", "v1=00, "+sig, "1700000000", body, now); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"wrong secret":   ok("other", sig, "1700000000", body, now),
		"tampered body":  ok("s3cret", sig, "1700000000", []byte(`{"a":2}`), now),
		"other ts":       ok("s3cret", sig, "1700000001", body, now),
		"too old":        ok("s3cret", sig, "1700000000", body, now.Add(6*time.Minute)),
		"from future":    ok("s3cret", sig, "1700000000", body, now.Add(-6*time.Minute)),
		"bad ts":         ok("s3cret", sig, "yesterday", body, now),
		"missing header": ok("s3cret", "", "1700000000", body, now),
	} {
		if err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

func tlsGuard(srv *httptest.Server) *netguard.Guard {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &netguard.Guard{AllowPrivate: true, TLSConfig: &tls.Config{RootCAs: pool}}
}

func sample() notify.Notification {
	sev := "critical"
	return notify.Notification{
		Version: notify.PayloadVersion, ID: "n-1", DeliveryID: "d-1", Kind: notify.KindAlert,
		CreatedAt: time.Unix(1700000000, 0).UTC(), Rule: &notify.RuleRef{ID: "r-1", Name: "Critical"},
		Summary: "New finding",
		Events: []notify.Event{{ID: 7, Type: notify.EventFindingOpened, Host: &notify.Host{ID: "h", Hostname: "web-1"},
			Finding: &notify.Finding{ID: "f", VulnKey: "CVE-2024-1", Severity: sev, SeverityRank: 6, KEV: true}}},
	}
}

func TestSendSignsAndPosts(t *testing.T) {
	var got struct {
		body    []byte
		headers http.Header
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.body, _ = io.ReadAll(r.Body)
		got.headers = r.Header.Clone()
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("thanks"))
	}))
	defer srv.Close()

	n := New(tlsGuard(srv))
	n.Now = func() time.Time { return time.Unix(1700000100, 0) }
	cfg := notify.Config{"url": srv.URL + "/hook", "secret": "whsec_abc"}
	res, err := n.Send(context.Background(), cfg, sample())
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusAccepted || res.Response != "thanks" {
		t.Fatalf("result %+v", res)
	}
	h := got.headers
	if h.Get("Content-Type") != "application/json" || h.Get(HeaderDelivery) != "d-1" ||
		h.Get(HeaderKind) != "alert" || h.Get(HeaderTimestamp) != "1700000100" || h.Get("User-Agent") != UserAgent {
		t.Fatalf("headers %v", h)
	}
	if err := Verify("whsec_abc", h.Get(HeaderSignature), h.Get(HeaderTimestamp), got.body,
		time.Unix(1700000100, 0), 5*time.Minute); err != nil {
		t.Fatalf("signature: %v", err)
	}
	var decoded notify.Notification
	if err := json.Unmarshal(got.body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Version != 1 || decoded.Events[0].Finding.VulnKey != "CVE-2024-1" || decoded.Rule.Name != "Critical" {
		t.Fatalf("payload %s", got.body)
	}
}

func TestSendClassifiesResponses(t *testing.T) {
	code := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if code == http.StatusFound {
			w.Header().Set("Location", "https://elsewhere.invalid/")
		}
		w.WriteHeader(code)
	}))
	defer srv.Close()
	n := New(tlsGuard(srv))
	cfg := notify.Config{"url": srv.URL, "secret": "x"}
	for c, wantPermanent := range map[int]bool{
		500: false, 502: false, 503: false, 429: false, 408: false,
		400: true, 401: true, 404: true, 410: true, 302: true,
	} {
		code = c
		res, err := n.Send(context.Background(), cfg, sample())
		if err == nil {
			t.Errorf("%d: no error", c)
			continue
		}
		if notify.IsPermanent(err) != wantPermanent {
			t.Errorf("%d: permanent = %v, want %v (%v)", c, notify.IsPermanent(err), wantPermanent, err)
		}
		if c != 302 && res.StatusCode != c {
			t.Errorf("%d: status %d", c, res.StatusCode)
		}
	}
}

// The strict (production) guard refuses the loopback test server: a
// permanent failure, never retried.
func TestSendBlocksPrivateDestinations(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached a loopback server")
	}))
	defer srv.Close()
	g := tlsGuard(srv)
	g.AllowPrivate = false
	n := New(g)
	for _, u := range []string{srv.URL, "https://127.0.0.1/", "https://169.254.169.254/latest/meta-data", "http://example.com/"} {
		_, err := n.Send(context.Background(), notify.Config{"url": u, "secret": "x"}, sample())
		if !notify.IsPermanent(err) || !errors.Is(err, netguard.ErrBlocked) {
			t.Errorf("%s: want permanent ErrBlocked, got %v", u, err)
		}
	}
}

func TestValidate(t *testing.T) {
	n := New(&netguard.Guard{})
	if err := n.Validate(notify.Config{"url": "https://example.com/h", "secret": "s"}); err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]notify.Config{
		"no url":    {"secret": "s"},
		"no secret": {"url": "https://example.com/h"},
		"http":      {"url": "http://example.com/h", "secret": "s"},
		"private":   {"url": "https://10.1.2.3/h", "secret": "s"},
	} {
		if err := n.Validate(cfg); err == nil {
			t.Errorf("%s: valid", name)
		}
	}
}
