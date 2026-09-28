package render

import (
	"fmt"
	"strings"

	"github.com/pippinmole/upkeep.sh/server/internal/reports"
)

// reportLines are the headline numbers a report's text lists, in order:
// label and Headline JSON key (the key of Changes.Metrics).
var reportLines = []struct{ label, key string }{
	{"Patch now (KEV)", "patch_now"},
	{"Patch this week", "patch_this_week"},
	{"When convenient", "when_convenient"},
	{"Images to update", "images_to_update"},
	{"Reboots required", "reboots_required"},
	{"No fix available yet", "no_fix_findings"},
	{"Open findings", "total_open_findings"},
	{"Opened since last report", "opened_since_last"},
	{"Resolved since last report", "resolved_since_last"},
	{"Agents not reporting", "stale_agents"},
}

func headlineValue(h reports.Headline, key string) int {
	switch key {
	case "patch_now":
		return h.PatchNow
	case "patch_this_week":
		return h.PatchThisWeek
	case "when_convenient":
		return h.WhenConvenient
	case "images_to_update":
		return h.ImagesToUpdate
	case "reboots_required":
		return h.RebootsRequired
	case "no_fix_findings":
		return h.NoFixFindings
	case "total_open_findings":
		return h.TotalOpenFindings
	case "opened_since_last":
		return h.OpenedSinceLast
	case "resolved_since_last":
		return h.ResolvedSinceLast
	case "stale_agents":
		return h.StaleAgents
	}
	return 0
}

// ReportHeadline is a report's headline numbers as plain-text lines, each
// with its change since the previous report when there is one ("Open
// findings: 42 (+12, +40%)"; the percentage only when the snapshot has
// one, see reports.MetricChange), for ntfy bodies and plain-text email.
func ReportHeadline(s reports.Snapshot) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Estate: %s, %s, %s\n",
		plural(s.Estate.Hosts, "host", "hosts"), plural(s.Estate.Containers, "container", "containers"),
		plural(s.Estate.Images, "image", "images"))
	for _, l := range reportLines {
		fmt.Fprintf(&b, "%s: %d", l.label, headlineValue(s.Headline, l.key))
		if s.Changes != nil {
			if m, ok := s.Changes.Metrics[l.key]; ok {
				b.WriteString(" (" + delta(m) + ")")
			}
		}
		b.WriteByte('\n')
	}
	switch {
	case s.Changes == nil:
		b.WriteString("\nFirst report of this schedule: no comparison yet.")
	case !s.Changes.Comparable:
		b.WriteString("\nThe report's ranking rules changed since the previous report; only numbers that don't depend on them are compared.")
	default:
		b.WriteString("\nChanges since the previous report of " + s.Changes.PreviousGeneratedAt.UTC().Format("2006-01-02") + ".")
	}
	return b.String()
}

// delta is "+3", "-2", "+12, +40%" or "no change".
func delta(m reports.MetricChange) string {
	if m.Delta == 0 {
		return "no change"
	}
	s := fmt.Sprintf("%+d", m.Delta)
	if m.Percent != nil {
		s += ", " + strings.TrimSuffix(strings.TrimSuffix(fmt.Sprintf("%+.1f", *m.Percent), "0"), ".") + "%"
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
