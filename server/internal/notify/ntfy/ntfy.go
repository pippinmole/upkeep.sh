// Package ntfy is the "ntfy" channel type: a push notification published
// to a topic on an ntfy server (https://ntfy.sh or self-hosted), rendered
// for humans: a title, a short plain-text body, a priority derived from
// severity/KEV, emoji tags and a link to the dashboard. Format and priority
// mapping: docs/ARCHITECTURE.md "ntfy channel".
//
// Publishing uses ntfy's JSON API (POST {"topic": ..., "title": ...} to the
// server root) rather than POST /<topic> with X-Title/X-Priority/X-Tags
// headers: titles and bodies carry package names, host names and agent
// names verbatim, and JSON encodes any UTF-8 safely, while header values
// would need RFC 2047 encoding and sanitizing against CR/LF. Tags are a
// real array instead of a comma-joined header, and the topic travels in the
// body, so it never needs path escaping.
package ntfy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pippinmole/upkeep.sh/server/internal/netguard"
	"github.com/pippinmole/upkeep.sh/server/internal/notify"
	"github.com/pippinmole/upkeep.sh/server/internal/notify/render"
	"github.com/pippinmole/upkeep.sh/server/internal/reports"
)

const (
	Type = "ntfy"

	// DefaultServer is used when the server URL field is left blank.
	DefaultServer = "https://ntfy.sh"
	UserAgent     = "upkeep.sh-ntfy/1"

	// Timeout bounds one attempt, including reading the response.
	Timeout = 10 * time.Second

	// maxResponse is how much of the response body is kept for the delivery
	// log; maxErrBody is how much of it goes into an error message.
	maxResponse = 4 << 10
	maxErrBody  = 300

	// maxMessage keeps the body under ntfy's default message size limit
	// (4096 bytes); a longer message would be turned into an attachment.
	maxMessage = 3500
	// maxListed is how many events a multi-event message lists.
	maxListed = 10
)

// ntfy priorities.
const (
	PriorityMin     = 1
	PriorityLow     = 2
	PriorityDefault = 3
	PriorityHigh    = 4
	PriorityUrgent  = 5
)

// PriorityAuto (or a blank priority field) derives the priority from the
// events; any other value of the priority field is a fixed priority 1-5.
const PriorityAuto = "auto"

// topicRE is ntfy's own topic rule (server/server.go topicRegex).
var topicRE = regexp.MustCompile(`^[-_A-Za-z0-9]{1,64}$`)

// Notifier is the ntfy channel type.
type Notifier struct {
	Guard  *netguard.Guard
	client *http.Client
}

func New(g *netguard.Guard) *Notifier {
	return &Notifier{Guard: g, client: g.Client(Timeout)}
}

func (n *Notifier) Spec() notify.Spec {
	return notify.Spec{
		Type:        Type,
		Label:       "ntfy",
		Description: "Push notifications to your phone or desktop via an ntfy topic (ntfy.sh or self-hosted).",
		Fields: []notify.Field{
			{
				Key: "server", Label: "Server URL", Type: notify.FieldURL, MaxLength: 2048,
				Placeholder: DefaultServer,
				Help: "Leave blank for ntfy.sh. A self-hosted server must be reachable over public https " +
					"on port 443 or 8443; private and internal addresses are refused.",
			},
			{
				Key: "topic", Label: "Topic", Type: notify.FieldText, Required: true, MaxLength: 64,
				Placeholder: "upkeep-alerts-7f3k9q",
				Help: "Letters, digits, - and _ only. Topics on ntfy.sh are public to anyone who " +
					"knows the name, so pick a hard-to-guess one or use an access token.",
			},
			{
				Key: "token", Label: "Access token", Type: notify.FieldSecret, Secret: true, MaxLength: 256,
				Placeholder: "tk_…",
				Help:        "Optional. For protected topics: sent as a Bearer token.",
			},
			{
				Key: "priority", Label: "Priority", Type: notify.FieldSelect,
				Placeholder: "Automatic (by severity)",
				Help:        "Automatic: urgent for KEV or critical findings, low for resolved ones and recoveries.",
				Options: []notify.Option{
					{Value: PriorityAuto, Label: "Automatic (by severity)"},
					{Value: "5", Label: "Urgent (5)"},
					{Value: "4", Label: "High (4)"},
					{Value: "3", Label: "Default (3)"},
					{Value: "2", Label: "Low (2)"},
					{Value: "1", Label: "Min (1)"},
				},
			},
		},
	}
}

// serverURL returns the configured server, or DefaultServer.
func serverURL(cfg notify.Config) string {
	if s := strings.TrimSpace(cfg["server"]); s != "" {
		return s
	}
	return DefaultServer
}

func (n *Notifier) Validate(cfg notify.Config) error {
	if err := notify.ValidateRequired(n.Spec(), cfg); err != nil {
		return err
	}
	if !topicRE.MatchString(cfg["topic"]) {
		return errors.New("topic may only contain letters, digits, - and _ (at most 64)")
	}
	if t := cfg["token"]; t != "" && strings.ContainsFunc(t, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return errors.New("access token must not contain spaces or control characters")
	}
	u, err := n.Guard.CheckURL(serverURL(cfg))
	if err != nil {
		return fmt.Errorf("server URL: %w", err)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("server URL must not have a query or fragment")
	}
	return nil
}

// Message is ntfy's JSON publish body (https://docs.ntfy.sh/publish/#publish-as-json).
type Message struct {
	Topic    string   `json:"topic"`
	Title    string   `json:"title,omitempty"`
	Message  string   `json:"message"`
	Priority int      `json:"priority,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Click    string   `json:"click,omitempty"`
}

// Render turns a notification into the ntfy message for topic, with the
// priority chosen by the priority field value (PriorityAuto or blank:
// derived from the events).
func Render(topic, priority string, n notify.Notification) Message {
	m := Message{Topic: topic}
	switch {
	case n.Kind == notify.KindTest:
		m.Title = n.Summary
		if m.Title == "" {
			m.Title = "Test notification from upkeep.sh"
		}
		m.Message = "Your ntfy channel works. Alerts matching your rules will arrive here."
		m.Priority = PriorityDefault
		m.Tags = []string{"bell"}
	case n.Kind == notify.KindReport:
		m = renderReport(topic, n)
	case len(n.Events) == 1:
		e := n.Events[0]
		m.Title = render.Title(e)
		m.Message = render.Body(e)
		m.Priority = eventPriority(e)
		m.Tags = eventTags(e)
		m.Click = e.URL
	default:
		m.Title = n.Summary
		m.Message = render.List(n.Events, maxListed)
		top := 0
		for i, e := range n.Events {
			if p := eventPriority(e); p > m.Priority {
				m.Priority, top = p, i
			}
		}
		if len(n.Events) > 0 {
			m.Tags = eventTags(n.Events[top])
		}
		m.Click = render.CommonURL(n.Events)
	}
	if n.Kind == notify.KindDigest {
		if !strings.HasPrefix(m.Title, "Digest: ") {
			m.Title = "Digest: " + m.Title
		}
		// A digest is a periodic roundup the user chose over immediate
		// alerts; don't let it page them at urgent priority.
		m.Priority = min(m.Priority, PriorityHigh)
	}
	if n.Rule != nil && n.Rule.Name != "" {
		m.Message += "\n\nRule: " + n.Rule.Name
	}
	if p, err := strconv.Atoi(priority); err == nil && p >= PriorityMin && p <= PriorityUrgent {
		m.Priority = p
	}
	m.Title = render.Truncate(m.Title, 250)
	m.Message = render.Truncate(m.Message, maxMessage)
	return m
}

// renderReport: the report's summary line as the title
// ("Monday patch list: 1 urgent action, …", reports.Title), the headline
// numbers with their changes as the body, and click to the report page.
// Priority 3, or 4 when there is something to patch now (KEV): a report is
// a scheduled roundup of state, not a new event, so it never pages at 5.
func renderReport(topic string, n notify.Notification) Message {
	m := Message{Topic: topic, Title: n.Summary, Priority: PriorityDefault, Tags: []string{"clipboard"}}
	if n.Report == nil || n.Report.Snapshot == nil {
		m.Message = "The report is no longer available."
		return m
	}
	s := *n.Report.Snapshot
	m.Title = reports.Title(s)
	m.Message = render.ReportHeadline(s)
	m.Click = n.Report.URL
	if s.Headline.PatchNow > 0 {
		m.Priority = PriorityHigh
		m.Tags = append(m.Tags, "kev")
	}
	return m
}

// eventPriority maps one event to an ntfy priority:
//
//	resolved:                          2 low
//	firing, vulnerability rule:        KEV or critical -> 5 urgent, high -> 4,
//	                                   medium -> 3, anything lower/unknown -> 2
//	firing, host not seen:             4 high (monitoring has stopped)
//	firing, any other property:        3 default
func eventPriority(e notify.Event) int {
	switch {
	case e.Type == notify.EventAlertResolved:
		return PriorityLow
	case e.Finding != nil:
		if render.IsKEVOrCritical(e.Finding) {
			return PriorityUrgent
		}
		switch strings.ToLower(e.Finding.Severity) {
		case "high":
			return PriorityHigh
		case "medium":
			return PriorityDefault
		}
		return PriorityLow
	case e.Alert != nil && e.Alert.Property == "host_not_seen":
		return PriorityHigh
	}
	return PriorityDefault
}

// eventTags are ntfy tags; ones that match an emoji short code are shown
// as that emoji before the title.
func eventTags(e notify.Event) []string {
	var tags []string
	switch {
	case e.Type == notify.EventAlertResolved:
		tags = append(tags, "white_check_mark")
	case e.Finding != nil && render.IsKEVOrCritical(e.Finding):
		tags = append(tags, "rotating_light")
	case e.Finding != nil && strings.EqualFold(e.Finding.Severity, "high"):
		tags = append(tags, "warning")
	case e.Finding != nil:
		tags = append(tags, "mag")
	case e.Alert != nil && e.Alert.Property == "host_not_seen":
		tags = append(tags, "electric_plug")
	default:
		tags = append(tags, "bell")
	}
	if e.Finding != nil {
		if e.Finding.KEV {
			tags = append(tags, "kev")
		}
		if e.Finding.Severity != "" {
			tags = append(tags, strings.ToLower(e.Finding.Severity))
		}
	}
	if e.Host != nil && e.Host.Hostname != "" {
		tags = append(tags, e.Host.Hostname)
	}
	return tags
}

func (n *Notifier) Send(ctx context.Context, cfg notify.Config, note notify.Notification) (notify.Result, error) {
	var res notify.Result
	if err := n.Validate(cfg); err != nil {
		return res, notify.Permanent(err)
	}
	body, err := json.Marshal(Render(cfg["topic"], cfg["priority"], note))
	if err != nil {
		return res, notify.Permanent(err)
	}
	// JSON publishing goes to the server root; a path (reverse proxy
	// prefix) is kept.
	endpoint := strings.TrimRight(serverURL(cfg), "/") + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return res, notify.Permanent(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	if t := cfg["token"]; t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}

	client := n.client
	if client == nil {
		client = n.Guard.Client(Timeout)
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
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	raw := strings.ToValidUTF8(string(b), string(utf8.RuneError))
	res.Response = render.Truncate(raw, maxResponse)

	code := resp.StatusCode
	if code >= 200 && code < 300 {
		return res, nil
	}
	err = fmt.Errorf("ntfy: HTTP %d: %s", code, errorText(raw))
	switch {
	case code == http.StatusRequestTimeout, code == http.StatusTooEarly, code == http.StatusTooManyRequests, code >= 500:
		return res, err // retried with backoff
	case code >= 300 && code < 400:
		return res, notify.Permanent(fmt.Errorf("%w (redirect not followed)", err))
	default:
		return res, notify.Permanent(err)
	}
}

// errorText is ntfy's error message: the "error" of its JSON error body
// ({"code":40301,"http":403,"error":"forbidden",...}), else the start of
// the raw body.
func errorText(body string) string {
	var e struct {
		Code  int    `json:"code"`
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(body), &e) == nil && e.Error != "" {
		if e.Code != 0 {
			return fmt.Sprintf("%s (code %d)", e.Error, e.Code)
		}
		return e.Error
	}
	body = strings.TrimSpace(body)
	if body == "" {
		return "empty response"
	}
	return render.Truncate(body, maxErrBody)
}
