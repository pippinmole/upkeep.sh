package reports

import (
	"cmp"
	"math"
	"slices"
)

// PercentMinPrevious is the smallest previous value a percentage change
// is shown for (0 -> 3 is not "+inf%", 1 -> 2 is not "+100%").
const PercentMinPrevious = 10

// rankingIndependent lists the headline metrics whose definition doesn't
// depend on RankingVersion, so they are still compared when the previous
// report used other rules: every open finding counts toward the total
// whatever its tier, opened / resolved count findings lifecycle
// transitions, and staleness is the agents' own rule (agent_health), not
// the report's. Tiers, images to update, reboots and "no fix" are the
// report's definitions (see RankingVersion) and are left out.
var rankingIndependent = map[string]bool{
	"total_open_findings": true,
	"opened_since_last":   true,
	"resolved_since_last": true,
	"stale_agents":        true,
}

// metrics returns the headline numbers keyed by their JSON key.
func (h Headline) metrics() map[string]int {
	return map[string]int{
		"patch_now":           h.PatchNow,
		"patch_this_week":     h.PatchThisWeek,
		"when_convenient":     h.WhenConvenient,
		"images_to_update":    h.ImagesToUpdate,
		"reboots_required":    h.RebootsRequired,
		"no_fix_findings":     h.NoFixFindings,
		"total_open_findings": h.TotalOpenFindings,
		"opened_since_last":   h.OpenedSinceLast,
		"resolved_since_last": h.ResolvedSinceLast,
		"stale_agents":        h.StaleAgents,
	}
}

// contribution is a host's share of the headline metrics, keyed like
// Headline; only metrics it has a share of (non-zero).
func (h HostSummary) contribution(keep func(string) bool) map[string]int {
	out := map[string]int{}
	add := func(k string, v int) {
		if v != 0 && keep(k) {
			out[k] = v
		}
	}
	add("patch_now", h.PatchNow)
	add("patch_this_week", h.PatchThisWeek)
	add("when_convenient", h.WhenConvenient)
	add("images_to_update", h.ImagesToUpdate)
	add("reboots_required", boolInt(h.RebootRequired))
	add("no_fix_findings", h.NoFixFindings)
	add("total_open_findings", h.TotalOpenFindings)
	return out
}

// Compare compares a report with the previous report of its schedule
// (prev, stored as prevReportID); nil when there is none. Every headline
// metric gets an absolute change, and a percentage when the previous
// value is at least PercentMinPrevious. When prev was built under another
// RankingVersion the comparison is not Comparable: only the
// ranking-independent metrics are compared, and hosts' contributions are
// limited to them too. Hosts are matched by id: in cur and not prev =
// added, the reverse = archived (or deleted), each with its share from
// the report it appears in.
func Compare(prev *Snapshot, prevReportID string, cur Snapshot) *Changes {
	if prev == nil {
		return nil
	}
	c := &Changes{
		PreviousReportID:    prevReportID,
		PreviousGeneratedAt: prev.GeneratedAt.UTC(),
		Comparable:          prev.RankingVersion == cur.RankingVersion,
		Metrics:             map[string]MetricChange{},
		HostsAdded:          []HostChange{},
		HostsArchived:       []HostChange{},
	}
	keep := func(k string) bool { return c.Comparable || rankingIndependent[k] }

	pm, cm := prev.Headline.metrics(), cur.Headline.metrics()
	for k, v := range cm {
		if keep(k) {
			c.Metrics[k] = metricChange(pm[k], v)
		}
	}

	c.HostsAdded = hostDiff(cur.Hosts, prev.Hosts, keep)
	c.HostsArchived = hostDiff(prev.Hosts, cur.Hosts, keep)
	return c
}

func metricChange(prev, cur int) MetricChange {
	m := MetricChange{Previous: prev, Current: cur, Delta: cur - prev}
	if prev >= PercentMinPrevious {
		p := math.Round(float64(m.Delta)/float64(prev)*1000) / 10
		m.Percent = &p
	}
	return m
}

// hostDiff lists the hosts of in that are not in other, with their
// contribution in in.
func hostDiff(in, other []HostSummary, keep func(string) bool) []HostChange {
	seen := make(map[string]bool, len(other))
	for _, h := range other {
		seen[h.ID] = true
	}
	out := []HostChange{}
	for _, h := range in {
		if !seen[h.ID] {
			out = append(out, HostChange{ID: h.ID, Name: h.Name, Contribution: h.contribution(keep)})
		}
	}
	slices.SortFunc(out, func(a, b HostChange) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID)) })
	return out
}
