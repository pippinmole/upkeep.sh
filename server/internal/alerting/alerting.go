// Package alerting is the pure core of alert rule evaluation: which rules
// an event matches, dedup, digest scheduling, how matched events are cut
// into notifications, and their summary line. It knows nothing about
// channel types (internal/notify) or storage (store/alerting.go).
//
// Pipeline (docs/ARCHITECTURE.md "Alerting"):
//
//	transition (findings reconcile, agent health job)
//	  -> alert_events row, in the same transaction (outbox)
//	  -> alert_evaluate: for each event x enabled rule of its user:
//	       Match? -> Dedup (rule, type|subject) within the rule's window?
//	         immediate rule: batched per rule per evaluation pass -> notification
//	         digest rule:    alert_digest_items -> alert_digest when DigestDue
//	  -> one notification_deliveries row per rule channel -> alert_deliver
package alerting

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/notify"
)

// MaxEventsPerNotification caps one notification; more matched events are
// split over several.
const MaxEventsPerNotification = 200

// Rule is an alert_rules row.
type Rule struct {
	ID, WorkspaceID, Name string
	EventTypes            []string
	MinSeverityRank       int // 0 = any
	KEVOnly               bool
	HostIDs               []string // nil = all hosts
	DedupWindow           time.Duration
	Digest                bool
	DigestInterval        time.Duration
	LastDigestAt          *time.Time
	CreatedAt             time.Time
	FindingKinds          []string // findings.kind of finding events (alert_rules.finding_kinds); nil = any
}

// EventMeta is what rule matching needs to know about an alert_events row.
type EventMeta struct {
	ID           int64
	WorkspaceID  string
	Type         string
	Subject      string
	HostIDs      []string
	SeverityRank *int // finding events only
	KEV          bool
	// FindingKind is the finding's kind (finding events; "" = unknown,
	// e.g. an event written before kinds were recorded: not filtered).
	FindingKind string
}

// IsFindingEvent: severity / KEV filters apply only to these.
func IsFindingEvent(t string) bool { return strings.HasPrefix(t, "finding.") }

// Match reports whether rule r selects event e. The caller has already
// checked the rule is enabled.
func Match(r Rule, e EventMeta) bool {
	if r.WorkspaceID != e.WorkspaceID || !slices.Contains(r.EventTypes, e.Type) {
		return false
	}
	if IsFindingEvent(e.Type) {
		if r.MinSeverityRank > 0 && (e.SeverityRank == nil || *e.SeverityRank < r.MinSeverityRank) {
			return false
		}
		if r.KEVOnly && !e.KEV {
			return false
		}
		if r.FindingKinds != nil && e.FindingKind != "" && !slices.Contains(r.FindingKinds, e.FindingKind) {
			return false
		}
	}
	if r.HostIDs != nil && !slices.ContainsFunc(e.HostIDs, func(h string) bool { return slices.Contains(r.HostIDs, h) }) {
		return false
	}
	return true
}

// DedupKey identifies "the same alert" for a rule: an event type about a
// subject ("finding.opened|finding:<host>:pkg:openssl:CVE-...").
func DedupKey(e EventMeta) string { return e.Type + "|" + e.Subject }

// Suppressed reports whether a key last sent at lastSent (nil = never) is
// still inside the window at now.
func Suppressed(lastSent *time.Time, window time.Duration, now time.Time) bool {
	return window > 0 && lastSent != nil && now.Sub(*lastSent) < window
}

// DigestDue reports whether a digest rule with pending items should be
// flushed at now: its interval has elapsed since the last digest (or,
// before the first one, since the rule was created). A rule switched from
// digest to immediate is flushed at once.
func DigestDue(r Rule, now time.Time) bool {
	if !r.Digest {
		return true
	}
	since := r.CreatedAt
	if r.LastDigestAt != nil {
		since = *r.LastDigestAt
	}
	return !now.Before(since.Add(r.DigestInterval))
}

// Chunk splits events into notification-sized batches, keeping order.
func Chunk[T any](events []T) [][]T {
	var out [][]T
	for len(events) > 0 {
		n := min(len(events), MaxEventsPerNotification)
		out = append(out, events[:n])
		events = events[n:]
	}
	return out
}

var eventVerb = map[string]string{
	notify.EventFindingOpened:   "new",
	notify.EventFindingReopened: "reopened",
	notify.EventFindingResolved: "resolved",
	notify.EventAgentStale:      "agent stale",
	notify.EventAgentRecovered:  "agent recovered",
}

// Summary is the one-line description of a notification's events, e.g.
// `3 new, 1 resolved findings on web-1 (1 critical, 1 KEV)` or
// `Agent "db-agent" stale`.
func Summary(kind string, events []notify.Event) string {
	if kind == notify.KindTest {
		return "Test notification from upkeep.sh"
	}
	if len(events) == 0 {
		return "No events"
	}
	if len(events) == 1 {
		return describe(events[0])
	}
	counts := map[string]int{}
	var findingsN, crit, kev int
	hosts := map[string]bool{}
	for _, e := range events {
		counts[e.Type]++
		if e.Host != nil {
			hosts[e.Host.Hostname] = true
		}
		if e.Finding != nil {
			findingsN++
			if e.Finding.Severity == "critical" && e.Type != notify.EventFindingResolved {
				crit++
			}
			if e.Finding.KEV && e.Type != notify.EventFindingResolved {
				kev++
			}
		}
	}
	var parts []string
	for _, t := range notify.EventTypes {
		if counts[t] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[t], eventVerb[t]))
		}
	}
	s := strings.Join(parts, ", ")
	if findingsN == len(events) {
		s += " findings"
	}
	if len(hosts) == 1 {
		for h := range hosts {
			s += " on " + h
		}
	} else if len(hosts) > 1 {
		s += fmt.Sprintf(" across %d hosts", len(hosts))
	}
	var extra []string
	if crit > 0 {
		extra = append(extra, fmt.Sprintf("%d critical", crit))
	}
	if kev > 0 {
		extra = append(extra, fmt.Sprintf("%d KEV", kev))
	}
	if len(extra) > 0 {
		s += " (" + strings.Join(extra, ", ") + ")"
	}
	if kind == notify.KindDigest {
		s = "Digest: " + s
	}
	return s
}

func describe(e notify.Event) string {
	switch {
	case e.Finding != nil:
		host := ""
		if e.Host != nil {
			host = " on " + e.Host.Hostname
		}
		verb := map[string]string{
			notify.EventFindingOpened: "New", notify.EventFindingReopened: "Reopened",
			notify.EventFindingResolved: "Resolved",
		}[e.Type]
		kev := ""
		if e.Finding.KEV {
			kev = ", KEV"
		}
		in := e.Finding.SourcePackage
		if e.Finding.ImageID != "" {
			img := e.Finding.ImageID
			if len(e.Finding.ImageRefs) > 0 {
				img = e.Finding.ImageRefs[0]
			}
			in += " (image " + img + ")"
		}
		return fmt.Sprintf("%s finding %s in %s%s (%s%s)", verb,
			e.Finding.VulnKey, in, host, e.Finding.Severity, kev)
	case e.Agent != nil:
		if e.Type == notify.EventAgentStale {
			return fmt.Sprintf("Agent %q stopped reporting", e.Agent.Name)
		}
		return fmt.Sprintf("Agent %q is reporting again", e.Agent.Name)
	default:
		return e.Type
	}
}
