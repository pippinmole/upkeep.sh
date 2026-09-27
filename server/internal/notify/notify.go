// Package notify is the channel-agnostic side of alert delivery: the
// Notifier interface every channel type implements, the declarative config
// schema the dashboard renders its forms from, a Registry of channel types,
// and the Notification model that is delivered.
//
// Rule evaluation and dispatch (internal/alerting, store/alerting.go,
// jobs/alerting.go) only ever talk to a Notifier through this package, so
// adding a channel type touches nothing there.
//
// # How to add a notifier (email, Discord, Slack, ntfy, ...)
//
//  1. Create internal/notify/<type> with a type implementing Notifier:
//     - Spec(): the type key (e.g. "slack"), label, description and its
//     Fields. Mark credentials Secret (stored in
//     notification_channels.secrets, write-only in the UI); mark a secret
//     Generated if the server should create it (shown once), like the
//     webhook signing secret.
//     - Validate(cfg): static checks of a channel's config (URL shape via
//     netguard.CheckURL, required fields, formats). Runs at send time, and
//     the "send test" button surfaces its error.
//     - Send(ctx, cfg, n): deliver one Notification. Make every outbound
//     HTTP request through a netguard.Guard client. Return a Result with the
//     status code, and wrap errors that retrying cannot fix with
//     Permanent(err); anything else is retried with backoff by the caller.
//  2. Register it in internal/notify/notifiers.Registry.
//  3. Regenerate the dashboard's copy of the schemas:
//     `go test ./internal/notify/notifiers -update` (writes
//     web/src/lib/notifier-types.json). The dashboard renders the channel
//     form from it; for a type that needs a custom form, register a
//     component in web/src/app/dashboard/notifications/channel-forms.tsx.
//
// That's all: rules, evaluation, dedup, digests, retries and the delivery
// log are shared.
package notify

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"
)

// FieldType is how the dashboard renders and validates a config field.
type FieldType string

const (
	FieldText   FieldType = "text"
	FieldURL    FieldType = "url"
	FieldEmail  FieldType = "email"
	FieldSecret FieldType = "secret" // masked; with Generated, created by the server
	FieldSelect FieldType = "select"
	FieldBool   FieldType = "bool"
)

// Option is one choice of a FieldSelect.
type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// Field is one config value of a channel type.
type Field struct {
	Key         string    `json:"key"`
	Label       string    `json:"label"`
	Type        FieldType `json:"type"`
	Help        string    `json:"help,omitempty"`
	Placeholder string    `json:"placeholder,omitempty"`
	Required    bool      `json:"required,omitempty"`
	// Secret values are stored apart from the rest of the config and never
	// shown again after they are saved.
	Secret bool `json:"secret,omitempty"`
	// Generated secrets are created by the server (never typed by the
	// user) and shown once, at creation or rotation.
	Generated bool     `json:"generated,omitempty"`
	MaxLength int      `json:"maxLength,omitempty"`
	Options   []Option `json:"options,omitempty"`
}

// Spec declares a channel type.
type Spec struct {
	Type        string  `json:"type"`
	Label       string  `json:"label"`
	Description string  `json:"description"`
	Fields      []Field `json:"fields"`
}

// Config is a channel's stored config merged with its secrets.
type Config map[string]string

// Result is what a delivery attempt got back.
type Result struct {
	StatusCode int    // 0 when no response was received
	Response   string // start of the response body, for the delivery log
}

// Notifier delivers notifications for one channel type.
type Notifier interface {
	Spec() Spec
	Validate(cfg Config) error
	Send(ctx context.Context, cfg Config, n Notification) (Result, error)
}

// permanentError marks a failure retrying cannot fix.
type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

// Permanent wraps err so the dispatcher stops retrying.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return permanentError{err}
}

// IsPermanent reports whether err (or anything it wraps) is Permanent.
func IsPermanent(err error) bool {
	var p permanentError
	return errors.As(err, &p)
}

// ValidateRequired checks the Required fields of spec are set in cfg; a
// helper for Validate implementations.
func ValidateRequired(spec Spec, cfg Config) error {
	for _, f := range spec.Fields {
		if f.Required && cfg[f.Key] == "" {
			return fmt.Errorf("%s is required", f.Label)
		}
		if f.MaxLength > 0 && len(cfg[f.Key]) > f.MaxLength {
			return fmt.Errorf("%s is longer than %d characters", f.Label, f.MaxLength)
		}
		if f.Type == FieldSelect && cfg[f.Key] != "" &&
			!slices.ContainsFunc(f.Options, func(o Option) bool { return o.Value == cfg[f.Key] }) {
			return fmt.Errorf("%s: invalid choice %q", f.Label, cfg[f.Key])
		}
	}
	return nil
}

// Registry maps channel type keys to their Notifier.
type Registry struct {
	byType map[string]Notifier
}

func NewRegistry(ns ...Notifier) *Registry {
	r := &Registry{byType: map[string]Notifier{}}
	for _, n := range ns {
		r.Register(n)
	}
	return r
}

// Register adds a channel type; registering a type key twice panics.
func (r *Registry) Register(n Notifier) {
	t := n.Spec().Type
	if t == "" {
		panic("notify: notifier with empty type")
	}
	if _, dup := r.byType[t]; dup {
		panic("notify: duplicate notifier type " + t)
	}
	r.byType[t] = n
}

// Get returns the Notifier for a type key.
func (r *Registry) Get(t string) (Notifier, bool) {
	n, ok := r.byType[t]
	return n, ok
}

// Specs lists every registered type's Spec, sorted by type key.
func (r *Registry) Specs() []Spec {
	out := make([]Spec, 0, len(r.byType))
	for _, n := range r.byType {
		out = append(out, n.Spec())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// ---- The notification model (the webhook payload; see docs/WEBHOOKS.md) ----

// PayloadVersion is Notification.Version; bump it on breaking changes.
const PayloadVersion = 1

// Notification kinds.
const (
	KindAlert  = "alert"  // immediate: one evaluation pass's matches for a rule
	KindDigest = "digest" // a rule's matches over its digest interval
	KindTest   = "test"   // "send test" from the dashboard
)

// Notification is one message to deliver, identical for every channel.
type Notification struct {
	Version    int       `json:"version"`
	ID         string    `json:"id"`          // notifications.id
	DeliveryID string    `json:"delivery_id"` // notification_deliveries.id, stable across retries
	Kind       string    `json:"kind"`
	CreatedAt  time.Time `json:"created_at"`
	Rule       *RuleRef  `json:"rule"`
	// Summary is a one-line, human-readable description (chat notifiers
	// use it as the message title).
	Summary string  `json:"summary"`
	Events  []Event `json:"events"`
}

// RuleRef names the rule that produced a notification (nil for tests).
type RuleRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Event types.
const (
	EventFindingOpened   = "finding.opened"
	EventFindingReopened = "finding.reopened"
	EventFindingResolved = "finding.resolved"
	EventAgentStale      = "agent.stale"
	EventAgentRecovered  = "agent.recovered"
)

// EventTypes lists the event types rules can select, in display order.
var EventTypes = []string{
	EventFindingOpened, EventFindingReopened, EventFindingResolved,
	EventAgentStale, EventAgentRecovered,
}

// Event is one thing that happened. Exactly the objects relevant to its
// type are set; new event families (e.g. port exposure) add a new optional
// object rather than changing existing ones.
type Event struct {
	ID         int64     `json:"id"`
	Type       string    `json:"type"`
	OccurredAt time.Time `json:"occurred_at"`
	Host       *Host     `json:"host,omitempty"`
	Agent      *Agent    `json:"agent,omitempty"`
	Finding    *Finding  `json:"finding,omitempty"`
	URL        string    `json:"url,omitempty"` // dashboard link, when SW_DASHBOARD_URL is set
}

type Host struct {
	ID       string  `json:"id"`
	Hostname string  `json:"hostname"`
	Label    *string `json:"label,omitempty"`
}

type Agent struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	LastSeenAt *time.Time `json:"last_seen_at"`
	Hosts      []Host     `json:"hosts,omitempty"`
}

type Finding struct {
	ID               string   `json:"id"`
	Kind             string   `json:"kind"`
	VulnKey          string   `json:"vuln_key"`
	SourcePackage    string   `json:"source_package,omitempty"`
	Packages         []string `json:"packages,omitempty"`
	InstalledVersion string   `json:"installed_version,omitempty"`
	FixedVersion     *string  `json:"fixed_version"`
	FixChannel       *string  `json:"fix_channel"`
	Severity         string   `json:"severity"`
	SeverityRank     int      `json:"severity_rank"`
	KEV              bool     `json:"kev"`
	EPSS             *float64 `json:"epss"`
	Status           string   `json:"status"`
	FirstSeenAt      string   `json:"first_seen_at,omitempty"`
}
