package alerting

import (
	"bytes"
	"encoding/json"
)

// Alert instance states and resolution reasons (alert_instances).
const (
	StateFiring   = "firing"
	StateResolved = "resolved"

	// ReasonCleared: the condition stopped matching. The only resolution
	// that notifies (when the rule has notify_on_resolve).
	ReasonCleared = "cleared"
	// Silent bookkeeping resolutions.
	ReasonRuleChanged  = "rule_changed"
	ReasonRuleDisabled = "rule_disabled"
	ReasonRuleDeleted  = "rule_deleted"
	ReasonOutOfScope   = "out_of_scope"
	ReasonHostArchived = "host_archived"
)

// Notifies reports whether a resolution with this reason is news.
func Notifies(reason string) bool { return reason == ReasonCleared }

// Match is one (host, subject) a condition currently matches.
type Match struct {
	HostID  string
	Subject string // "" for host-level properties
	Title   string
	// Details is property-specific JSON (for vulnerability: the finding
	// object of the notification payload).
	Details json.RawMessage
}

// Key is the instance key within a rule.
func (m Match) Key() [2]string { return [2]string{m.HostID, m.Subject} }

// Result is what a property evaluator found for a set of hosts.
type Result struct {
	Matches []Match
	// Unknown hosts: the property couldn't be read (collector failed, no
	// inventory yet, OS unknown). Their firing instances are left as they
	// are: unknown is never a resolution.
	Unknown map[string]bool
}

// Firing is a firing alert_instances row.
type Firing struct {
	ID, HostID, Subject string
	Condition           json.RawMessage // the rule's condition when it last matched
	Title               string
	Details             json.RawMessage
}

// Key is the instance key within a rule.
func (f Firing) Key() [2]string { return [2]string{f.HostID, f.Subject} }

// Resolution resolves a firing instance.
type Resolution struct {
	ID, Reason string
}

// Refresh updates a still-firing instance whose title, details or
// recorded condition changed.
type Refresh struct {
	ID    string
	Match Match
}

// Plan is what one evaluation of a rule changes.
type Plan struct {
	Fire    []Match
	Refresh []Refresh
	// Keep lists instances that still match unchanged (last_matched_at is
	// bumped).
	Keep    []string
	Resolve []Resolution
}

// HostStatus says how an evaluated rule relates to a host: evaluated
// (HostOK) or why it isn't (a resolution reason).
type HostStatus string

const HostOK HostStatus = ""

// Diff plans one rule's evaluation over a set of hosts.
//
//   - firing: the rule's firing instances on those hosts.
//   - res: the evaluator's result for the hosts that were evaluated.
//   - hosts: every host a firing instance is on, with its status; a host
//     missing from the map is treated as out of scope (e.g. deleted from
//     the rule's list).
//   - cond: the rule's current (canonical) condition.
//
// A match without a firing instance fires; a firing instance without a
// match resolves (cleared, or rule_changed when the condition was edited
// since it last matched), unless its host is unknown to the evaluator.
func Diff(firing []Firing, res Result, hosts map[string]HostStatus, cond []byte) Plan {
	var p Plan
	want := make(map[[2]string]Match, len(res.Matches))
	for _, m := range res.Matches {
		if st, ok := hosts[m.HostID]; ok && st == HostOK {
			want[m.Key()] = m
		}
	}
	have := make(map[[2]string]bool, len(firing))
	for _, f := range firing {
		have[f.Key()] = true
		st, known := hosts[f.HostID]
		switch {
		case !known:
			p.Resolve = append(p.Resolve, Resolution{f.ID, ReasonOutOfScope})
		case st != HostOK:
			p.Resolve = append(p.Resolve, Resolution{f.ID, string(st)})
		case res.Unknown[f.HostID]:
			// Can't tell: leave it firing, untouched.
		default:
			m, ok := want[f.Key()]
			switch {
			case !ok && !SameCondition(f.Condition, cond):
				p.Resolve = append(p.Resolve, Resolution{f.ID, ReasonRuleChanged})
			case !ok:
				p.Resolve = append(p.Resolve, Resolution{f.ID, ReasonCleared})
			case m.Title != f.Title || !sameJSON(m.Details, f.Details) || !SameCondition(f.Condition, cond):
				p.Refresh = append(p.Refresh, Refresh{f.ID, m})
			default:
				p.Keep = append(p.Keep, f.ID)
			}
		}
	}
	// Matches in the evaluator's order, so inserts are deterministic.
	for _, m := range res.Matches {
		if _, ok := want[m.Key()]; ok && !have[m.Key()] {
			p.Fire = append(p.Fire, m)
			have[m.Key()] = true // a duplicate match fires once
		}
	}
	return p
}

func sameJSON(a, b json.RawMessage) bool {
	if len(bytes.TrimSpace(a)) == 0 {
		a = json.RawMessage("{}")
	}
	if len(bytes.TrimSpace(b)) == 0 {
		b = json.RawMessage("{}")
	}
	return SameCondition(a, b)
}
