// Package ntfy is the "ntfy" channel type: a push notification published
// to a topic on an ntfy server (https://ntfy.sh or self-hosted), rendered
// for humans: a title, a short plain-text body, a priority derived from
// severity/KEV, emoji tags and a link to the dashboard. Format and priority
// mapping: docs/WEBHOOKS.md "ntfy".
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
	case len(n.Events) == 1:
		e := n.Events[0]
		m.Title = eventTitle(e)
		m.Message = eventBody(e)
		m.Priority = eventPriority(e)
		m.Tags = eventTags(e)
		m.Click = e.URL
	default:
		m.Title = n.Summary
		m.Message = listBody(n.Events)
		top := 0
		for i, e := range n.Events {
			if p := eventPriority(e); p > m.Priority {
				m.Priority, top = p, i
			}
		}
		if len(n.Events) > 0 {
			m.Tags = eventTags(n.Events[top])
		}
		m.Click = commonURL(n.Events)
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
	m.Title = truncate(m.Title, 250)
	m.Message = truncate(m.Message, maxMessage)
	return m
}

func isKEVOrCritical(f *notify.Finding) bool {
	return f.KEV || strings.EqualFold(f.Severity, "critical")
}

// eventPriority maps one event to an ntfy priority:
//
//	finding opened/reopened: KEV or critical -> 5 urgent, high -> 4,
//	                         medium -> 3, anything lower/unknown -> 2
//	finding resolved:        2 low
//	agent stale:             4 high (monitoring has stopped)
//	agent recovered:         2 low
func eventPriority(e notify.Event) int {
	switch e.Type {
	case notify.EventFindingOpened, notify.EventFindingReopened:
		if e.Finding == nil {
			return PriorityDefault
		}
		if isKEVOrCritical(e.Finding) {
			return PriorityUrgent
		}
		switch strings.ToLower(e.Finding.Severity) {
		case "high":
			return PriorityHigh
		case "medium":
			return PriorityDefault
		}
		return PriorityLow
	case notify.EventFindingResolved, notify.EventAgentRecovered:
		return PriorityLow
	case notify.EventAgentStale:
		return PriorityHigh
	}
	return PriorityDefault
}

// eventTags are ntfy tags; ones that match an emoji short code are shown
// as that emoji before the title.
func eventTags(e notify.Event) []string {
	var tags []string
	switch e.Type {
	case notify.EventFindingOpened, notify.EventFindingReopened:
		switch {
		case e.Finding != nil && isKEVOrCritical(e.Finding):
			tags = append(tags, "rotating_light")
		case e.Finding != nil && strings.EqualFold(e.Finding.Severity, "high"):
			tags = append(tags, "warning")
		default:
			tags = append(tags, "mag")
		}
	case notify.EventFindingResolved, notify.EventAgentRecovered:
		tags = append(tags, "white_check_mark")
	case notify.EventAgentStale:
		tags = append(tags, "electric_plug")
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

var findingVerb = map[string]string{
	notify.EventFindingOpened:   "opened",
	notify.EventFindingReopened: "reopened",
	notify.EventFindingResolved: "resolved",
}

// eventTitle, e.g. "KEV CVE-2024-3094 opened on web-1",
// "Critical CVE-2024-1 reopened on db", `Agent "edge" stopped reporting`.
func eventTitle(e notify.Event) string {
	switch {
	case e.Finding != nil:
		f := e.Finding
		prefix := ""
		switch {
		case f.KEV && e.Type != notify.EventFindingResolved:
			prefix = "KEV "
		case f.Severity != "" && e.Type != notify.EventFindingResolved:
			prefix = capitalize(f.Severity) + " "
		}
		verb := findingVerb[e.Type]
		if verb == "" {
			verb = e.Type
		}
		s := prefix + f.VulnKey + " " + verb
		if e.Host != nil {
			s += " on " + hostName(*e.Host)
		}
		return s
	case e.Agent != nil:
		if e.Type == notify.EventAgentStale {
			return fmt.Sprintf("Agent %q stopped reporting", e.Agent.Name)
		}
		return fmt.Sprintf("Agent %q is reporting again", e.Agent.Name)
	}
	return e.Type
}

func eventBody(e notify.Event) string {
	var lines []string
	switch {
	case e.Finding != nil:
		f := e.Finding
		pkg := f.SourcePackage
		if pkg == "" && len(f.Packages) > 0 {
			pkg = f.Packages[0]
		}
		if pkg != "" {
			line := "Package: " + pkg
			if f.InstalledVersion != "" {
				line += " " + f.InstalledVersion
			}
			if bins := otherPackages(pkg, f.Packages); bins != "" {
				line += " (" + bins + ")"
			}
			lines = append(lines, line)
		}
		switch {
		case e.Type == notify.EventFindingResolved:
			lines = append(lines, "No longer present on the host.")
		case f.FixedVersion != nil && *f.FixedVersion != "":
			fix := "Fix: upgrade to " + *f.FixedVersion
			if f.FixChannel != nil && *f.FixChannel != "" {
				fix += " (" + *f.FixChannel + ")"
			}
			lines = append(lines, fix)
		default:
			lines = append(lines, "Fix: none available yet")
		}
		risk := []string{"Severity: " + orUnknown(f.Severity)}
		if f.KEV {
			risk = append(risk, "known exploited (CISA KEV)")
		}
		if f.EPSS != nil {
			risk = append(risk, fmt.Sprintf("EPSS %.1f%%", *f.EPSS*100))
		}
		lines = append(lines, strings.Join(risk, ", "))
	case e.Agent != nil:
		if e.Agent.LastSeenAt != nil {
			lines = append(lines, "Last seen "+e.Agent.LastSeenAt.UTC().Format("2006-01-02 15:04 UTC"))
		}
		if len(e.Agent.Hosts) > 0 {
			names := make([]string, len(e.Agent.Hosts))
			for i, h := range e.Agent.Hosts {
				names[i] = hostName(h)
			}
			lines = append(lines, "Hosts: "+strings.Join(names, ", "))
		}
		if e.Type == notify.EventAgentStale {
			lines = append(lines, "Its hosts aren't being scanned until it reports again.")
		}
	}
	if len(lines) == 0 {
		return eventTitle(e)
	}
	return strings.Join(lines, "\n")
}

// listBody lists up to maxListed events, one line each.
func listBody(events []notify.Event) string {
	if len(events) == 0 {
		return "No events."
	}
	var b strings.Builder
	for i, e := range events {
		if i == maxListed {
			fmt.Fprintf(&b, "…and %d more", len(events)-maxListed)
			break
		}
		b.WriteString("• " + eventTitle(e))
		if e.Finding != nil && e.Finding.SourcePackage != "" {
			b.WriteString(" (" + e.Finding.SourcePackage + ")")
		}
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}

// commonURL is the link for a multi-event message: the events' URL if they
// all share one, else the dashboard root they point into (SW_DASHBOARD_URL
// + "/dashboard"); "" when events carry no links.
func commonURL(events []notify.Event) string {
	var first string
	same := true
	for _, e := range events {
		if e.URL == "" {
			continue
		}
		if first == "" {
			first = e.URL
		} else if e.URL != first {
			same = false
		}
	}
	if first == "" || same {
		return first
	}
	if i := strings.Index(first, "/dashboard/"); i >= 0 {
		return first[:i] + "/dashboard"
	}
	return ""
}

func otherPackages(src string, pkgs []string) string {
	var out []string
	for _, p := range pkgs {
		if p != src {
			out = append(out, p)
		}
	}
	if len(out) > 3 {
		out = append(out[:3], fmt.Sprintf("+%d more", len(out)-3))
	}
	return strings.Join(out, ", ")
}

func hostName(h notify.Host) string {
	if h.Label != nil && *h.Label != "" {
		return *h.Label
	}
	return h.Hostname
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// truncate cuts s to at most max bytes on a rune boundary, ending in "…".
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max - len("…")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
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
	res.Response = truncate(raw, maxResponse)

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
	return truncate(body, maxErrBody)
}
