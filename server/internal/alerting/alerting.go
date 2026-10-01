// Package alerting is the pure core of alert rules (docs/ALERTING.md):
// the property catalog and condition validation (catalog.go,
// condition.go), the per-rule state diff that turns current matches into
// alert instance transitions (state.go), digest scheduling, how
// transitions are cut into notifications, and their summary line. It
// knows nothing about channel types (internal/notify) or storage
// (store/alertrules*.go, store/alerting.go).
//
// Pipeline:
//
//	alert_rules_evaluate (worker; per host on ingest / findings change,
//	all hosts every minute): property evaluators -> Diff -> alert_instances
//	  -> alert_events outbox ('alert.firing' / 'alert.resolved'), same tx
//	  -> alert_evaluate: per rule, immediate notification or digest items
//	  -> one notification_deliveries row per rule channel -> alert_deliver
package alerting

import (
	"fmt"
	"strings"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/notify"
	"github.com/pippinmole/upkeep.sh/server/internal/notify/render"
)

// MaxEventsPerNotification caps one notification; more events are split
// over several.
const MaxEventsPerNotification = 200

// Rule is what notification dispatch needs of an alert_rules row.
type Rule struct {
	ID, WorkspaceID, Name string
	NotifyOnResolve       bool
	Digest                bool
	DigestInterval        time.Duration
	LastDigestAt          *time.Time
	CreatedAt             time.Time
}

// Sends reports whether an event of type t is sent for rule r.
func (r Rule) Sends(t string) bool {
	return t == notify.EventAlertFiring || (t == notify.EventAlertResolved && r.NotifyOnResolve)
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

// Summary is the one-line description of a notification's events, e.g.
// `Port 22/tcp is listening on web-1` for one event, or
// `3 firing, 1 resolved alerts on web-1 (1 critical, 1 KEV)`.
func Summary(kind string, events []notify.Event) string {
	if kind == notify.KindTest {
		return "Test notification from upkeep.sh"
	}
	if len(events) == 0 {
		return "No events"
	}
	var s string
	if len(events) == 1 {
		s = render.Title(events[0])
	} else {
		var firing, resolved, crit, kev int
		hosts := map[string]bool{}
		for _, e := range events {
			if e.Type == notify.EventAlertResolved {
				resolved++
			} else {
				firing++
				if e.Finding != nil && e.Finding.Severity == "critical" {
					crit++
				}
				if e.Finding != nil && e.Finding.KEV {
					kev++
				}
			}
			if e.Host != nil {
				hosts[render.HostName(*e.Host)] = true
			}
		}
		var parts []string
		if firing > 0 {
			parts = append(parts, fmt.Sprintf("%d firing", firing))
		}
		if resolved > 0 {
			parts = append(parts, fmt.Sprintf("%d resolved", resolved))
		}
		s = strings.Join(parts, ", ") + " alerts"
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
	}
	if kind == notify.KindDigest {
		s = "Digest: " + s
	}
	return s
}
