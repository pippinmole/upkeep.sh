package reports

import (
	"fmt"
	"strings"
)

// The one-line summary of a report: the ntfy title (here, in Go) and the
// email subject (web/src/lib/report-summary.ts) must produce the same text
// for the same snapshot, so change both together. Parts, in order, each
// only when > 0: urgent actions, to patch this week, images to update,
// hosts not reporting. No parts -> "all clear".

func count(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// StaleHostCount is the number of distinct hosts behind the stale agents
// (an agent can report for more than one host, and a host can in
// principle appear under two agents).
func StaleHostCount(s Snapshot) int {
	ids := map[string]bool{}
	for _, a := range s.Coverage.StaleAgents {
		for _, h := range a.Hosts {
			ids[h.ID] = true
		}
	}
	return len(ids)
}

// Summary is the report's one-line summary, e.g. "1 urgent action, 2 to
// patch this week, 1 image to update, 1 host not reporting".
func Summary(s Snapshot) string {
	h := s.Headline
	var parts []string
	if h.PatchNow > 0 {
		parts = append(parts, count(h.PatchNow, "urgent action", "urgent actions"))
	}
	if h.PatchThisWeek > 0 {
		parts = append(parts, fmt.Sprintf("%d to patch this week", h.PatchThisWeek))
	}
	if h.ImagesToUpdate > 0 {
		parts = append(parts, count(h.ImagesToUpdate, "image to update", "images to update"))
	}
	if n := StaleHostCount(s); n > 0 {
		parts = append(parts, count(n, "host not reporting", "hosts not reporting"))
	} else if h.StaleAgents > 0 {
		// Agents that never enrolled a host still leave the estate unwatched.
		parts = append(parts, count(h.StaleAgents, "agent not reporting", "agents not reporting"))
	}
	if len(parts) == 0 {
		return "all clear"
	}
	return strings.Join(parts, ", ")
}

// Title is "{schedule name}: {summary}": the ntfy title, the notification's
// summary, and (with the "[upkeep.sh] " prefix) the email subject.
func Title(s Snapshot) string {
	return s.Schedule.Name + ": " + Summary(s)
}
