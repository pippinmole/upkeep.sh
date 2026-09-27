// Package webhook is the "webhook" channel type: an HMAC-signed JSON POST
// of the notify.Notification to a user-supplied https URL. Wire format and
// the verification recipe: docs/WEBHOOKS.md.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pippinmole/upkeep.sh/server/internal/netguard"
	"github.com/pippinmole/upkeep.sh/server/internal/notify"
)

const (
	Type = "webhook"

	HeaderSignature = "X-Upkeep-Signature"
	HeaderTimestamp = "X-Upkeep-Timestamp"
	HeaderDelivery  = "X-Upkeep-Delivery"
	HeaderKind      = "X-Upkeep-Kind"
	UserAgent       = "upkeep.sh-webhook/1"

	// Timeout bounds one attempt, including reading the response.
	Timeout = 10 * time.Second
	// maxResponse is how much of the response body is read and kept.
	maxResponse = 1024
)

// Notifier is the webhook channel type.
type Notifier struct {
	Guard *netguard.Guard
	// Now is the signing clock (tests); nil = time.Now.
	Now func() time.Time

	client *http.Client
}

func New(g *netguard.Guard) *Notifier {
	return &Notifier{Guard: g, client: g.Client(Timeout)}
}

func (w *Notifier) Spec() notify.Spec {
	return notify.Spec{
		Type:        Type,
		Label:       "Webhook",
		Description: "HTTPS POST of a JSON payload, signed with HMAC-SHA256.",
		Fields: []notify.Field{
			{
				Key: "url", Label: "URL", Type: notify.FieldURL, Required: true, MaxLength: 2048,
				Placeholder: "https://example.com/hooks/upkeep",
				Help:        "Public https endpoint (port 443 or 8443). Private and internal addresses are refused.",
			},
			{
				Key: "secret", Label: "Signing secret", Type: notify.FieldSecret, Secret: true, Generated: true,
				Help: "Generated for you and shown once. Verify the X-Upkeep-Signature header with it (docs/WEBHOOKS.md).",
			},
		},
	}
}

func (w *Notifier) Validate(cfg notify.Config) error {
	if err := notify.ValidateRequired(w.Spec(), cfg); err != nil {
		return err
	}
	if cfg["secret"] == "" {
		return errors.New("signing secret is missing")
	}
	_, err := w.Guard.CheckURL(cfg["url"])
	return err
}

// Sign returns the X-Upkeep-Signature value for a body sent at timestamp
// ts: "v1=" + hex(HMAC-SHA256(secret, "<ts>.<body>")).
func Sign(secret string, ts int64, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(strconv.FormatInt(ts, 10)))
	m.Write([]byte{'.'})
	m.Write(body)
	return "v1=" + hex.EncodeToString(m.Sum(nil))
}

// Verify checks a signature header against body and timestamp, rejecting
// timestamps further than tolerance from now. The reference for receivers
// (docs/WEBHOOKS.md has the same recipe in other languages).
func Verify(secret, signatureHeader, timestampHeader string, body []byte, now time.Time, tolerance time.Duration) error {
	ts, err := strconv.ParseInt(timestampHeader, 10, 64)
	if err != nil {
		return errors.New("bad timestamp")
	}
	if d := now.Sub(time.Unix(ts, 0)); d > tolerance || d < -tolerance {
		return errors.New("timestamp outside tolerance")
	}
	want := Sign(secret, ts, body)
	for _, s := range strings.Split(signatureHeader, ",") {
		if hmac.Equal([]byte(strings.TrimSpace(s)), []byte(want)) {
			return nil
		}
	}
	return errors.New("signature mismatch")
}

func (w *Notifier) Send(ctx context.Context, cfg notify.Config, n notify.Notification) (notify.Result, error) {
	var res notify.Result
	if err := w.Validate(cfg); err != nil {
		return res, notify.Permanent(err)
	}
	body, err := json.Marshal(n)
	if err != nil {
		return res, notify.Permanent(err)
	}
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}
	ts := now().Unix()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg["url"], bytes.NewReader(body))
	if err != nil {
		return res, notify.Permanent(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(HeaderSignature, Sign(cfg["secret"], ts, body))
	req.Header.Set(HeaderDelivery, n.DeliveryID)
	req.Header.Set(HeaderKind, n.Kind)

	client := w.client
	if client == nil {
		client = w.Guard.Client(Timeout)
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, netguard.ErrBlocked) {
			return res, notify.Permanent(err)
		}
		return res, err
	}
	defer resp.Body.Close()
	res.StatusCode = resp.StatusCode
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	res.Response = strings.ToValidUTF8(string(b), string(utf8.RuneError))

	switch code := resp.StatusCode; {
	case code >= 200 && code < 300:
		return res, nil
	case code == http.StatusRequestTimeout, code == http.StatusTooEarly, code == http.StatusTooManyRequests, code >= 500:
		return res, fmt.Errorf("HTTP %d", code)
	case code >= 300 && code < 400:
		return res, notify.Permanent(fmt.Errorf("HTTP %d: redirect not followed", code))
	default:
		return res, notify.Permanent(fmt.Errorf("HTTP %d", code))
	}
}
