package email

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/notify/render"
	"github.com/pippinmole/upkeep.sh/server/internal/reports"
)

// Report emails are rendered by web (React Email) and sent from here
// (docs/decisions/report-email-html.md): the worker POSTs the stored
// snapshot to web's internal route and gets back {subject, html, text}.
const (
	// RenderPath is web's internal render route, under SW_WEB_INTERNAL_URL.
	RenderPath = "/api/internal/render/report"
	// RenderTimeout bounds one render request; with the SMTP Timeout it
	// stays inside alert_deliver's one-minute job timeout.
	RenderTimeout = 20 * time.Second
	// MaxRenderBytes caps the render response.
	MaxRenderBytes = 2 << 20

	maxRenderError = 300 // bytes of an error response kept in an error
)

// ReportRenderer calls web's internal render route. The URL is
// operator-configured and internal (e.g. http://web:3000 on the compose
// network), so the request deliberately does not go through netguard,
// which only allows public https destinations.
type ReportRenderer struct {
	url    string // SW_WEB_INTERNAL_URL + RenderPath
	secret string // SW_INTERNAL_RENDER_SECRET
	HTTP   *http.Client
}

// NewReportRenderer returns a renderer for web at baseURL (SW_WEB_INTERNAL_URL)
// authenticated with secret (SW_INTERNAL_RENDER_SECRET), or nil when either
// is empty: report emails are then sent as plain text.
func NewReportRenderer(baseURL, secret string) *ReportRenderer {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" || secret == "" {
		return nil
	}
	return &ReportRenderer{
		url:    baseURL + RenderPath,
		secret: secret,
		HTTP: &http.Client{
			Timeout: RenderTimeout,
			// The route never redirects; following one could forward the
			// bearer secret somewhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// RenderedReport is a report email as web rendered it.
type RenderedReport struct {
	Subject string // including SubjectPrefix, like web's reportEmailSubject
	HTML    string
	Text    string
}

// Render renders a report email. reportURL is the report page link, ""
// when SW_DASHBOARD_URL is unset. Every error is retryable (never
// notify.Permanent), whatever web answered: a failed render is retried
// like a failed send.
func (r *ReportRenderer) Render(ctx context.Context, snap *reports.Snapshot, reportURL string) (RenderedReport, error) {
	var out RenderedReport
	fail := func(format string, a ...any) (RenderedReport, error) {
		return out, fmt.Errorf("render report email: "+format, a...)
	}
	req := struct {
		Snapshot  *reports.Snapshot `json:"snapshot"`
		ReportURL *string           `json:"report_url"`
	}{Snapshot: snap}
	if reportURL != "" {
		req.ReportURL = &reportURL
	}
	body, err := json.Marshal(req)
	if err != nil {
		return fail("%v", err)
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return fail("%v", err)
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("Accept", "application/json")
	hreq.Header.Set("Authorization", "Bearer "+r.secret)
	resp, err := r.HTTP.Do(hreq)
	if err != nil {
		return fail("web unreachable: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxRenderBytes+1))
	if err != nil {
		return fail("reading web's response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fail("web returned %d: %s", resp.StatusCode, errorText(raw))
	}
	if len(raw) > MaxRenderBytes {
		return fail("web's response is larger than %d bytes", MaxRenderBytes)
	}
	var res struct {
		Subject *string `json:"subject"`
		HTML    *string `json:"html"`
		Text    *string `json:"text"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return fail("web's response is not the expected JSON: %v", err)
	}
	if res.Subject == nil || res.HTML == nil || res.Text == nil {
		return fail("web's response lacks subject, html or text")
	}
	out.Subject = sanitizeHeader(strings.ToValidUTF8(*res.Subject, "�"))
	if out.Subject == "" || out.Subject == strings.TrimSpace(SubjectPrefix) {
		return fail("web returned an empty subject")
	}
	if !strings.HasPrefix(out.Subject, SubjectPrefix) {
		out.Subject = SubjectPrefix + out.Subject
	}
	out.Subject = render.Truncate(out.Subject, len(SubjectPrefix)+maxSubject)
	out.HTML = strings.ToValidUTF8(*res.HTML, "�")
	out.Text = strings.ToValidUTF8(*res.Text, "�")
	if strings.TrimSpace(out.HTML) == "" || strings.TrimSpace(out.Text) == "" {
		return fail("web returned an empty html or text part")
	}
	return out, nil
}

// errorText is the start of an error response on one line.
func errorText(raw []byte) string {
	s := sanitizeHeader(strings.ToValidUTF8(string(raw), "�"))
	if s == "" {
		return "(empty response)"
	}
	return render.Truncate(s, maxRenderError)
}

// errRenderNotConfigured is only logged, never returned.
var errRenderNotConfigured = errors.New("report emails are sent as plain text: set SW_WEB_INTERNAL_URL and " +
	"SW_INTERNAL_RENDER_SECRET on the worker (and the same secret on web) for the HTML report email")
