package reports

import (
	"reflect"
	"testing"
	"time"
)

func snap(h Headline, hosts ...HostSummary) Snapshot {
	if hosts == nil {
		hosts = []HostSummary{}
	}
	return Snapshot{RankingVersion: RankingVersion, GeneratedAt: now, Headline: h, Hosts: hosts}
}

func TestCompareNoPrevious(t *testing.T) {
	if c := Compare(nil, "", snap(Headline{})); c != nil {
		t.Errorf("Compare(nil) = %+v", c)
	}
}

func TestComparePercentThreshold(t *testing.T) {
	prevAt := now.AddDate(0, 0, -7)
	prev := snap(Headline{PatchNow: 9, PatchThisWeek: 10, TotalOpenFindings: 12, ResolvedSinceLast: 20})
	prev.GeneratedAt = prevAt.In(time.FixedZone("x", 3600))
	cur := snap(Headline{PatchNow: 12, PatchThisWeek: 13, TotalOpenFindings: 14, ResolvedSinceLast: 17})
	c := Compare(&prev, "r-prev", cur)
	if c.PreviousReportID != "r-prev" || !c.PreviousGeneratedAt.Equal(prevAt) || c.PreviousGeneratedAt.Location() != time.UTC || !c.Comparable {
		t.Errorf("changes = %+v", c)
	}
	if len(c.Metrics) != 10 {
		t.Errorf("metrics = %v", c.Metrics)
	}
	check := func(key string, want MetricChange) {
		t.Helper()
		if got := c.Metrics[key]; !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %+v (percent %v), want %+v", key, got, deref(got.Percent), want)
		}
	}
	check("patch_now", MetricChange{Previous: 9, Current: 12, Delta: 3})                               // 9: no percent
	check("patch_this_week", MetricChange{Previous: 10, Current: 13, Delta: 3, Percent: fp(30)})       // 10: percent
	check("total_open_findings", MetricChange{Previous: 12, Current: 14, Delta: 2, Percent: fp(16.7)}) // one decimal
	check("resolved_since_last", MetricChange{Previous: 20, Current: 17, Delta: -3, Percent: fp(-15)})
	check("stale_agents", MetricChange{})
}

func TestCompareRankingVersionChanged(t *testing.T) {
	prev := snap(Headline{PatchNow: 5, TotalOpenFindings: 30, StaleAgents: 1, OpenedSinceLast: 2, ResolvedSinceLast: 1},
		HostSummary{ID: "gone", Name: "old-1", PatchNow: 2, NoFixFindings: 1, TotalOpenFindings: 4})
	prev.RankingVersion = RankingVersion - 1
	cur := snap(Headline{PatchNow: 7, TotalOpenFindings: 35})
	c := Compare(&prev, "r", cur)
	if c.Comparable {
		t.Error("comparable across ranking versions")
	}
	var keys []string
	for k := range c.Metrics {
		keys = append(keys, k)
	}
	want := map[string]bool{"total_open_findings": true, "opened_since_last": true, "resolved_since_last": true, "stale_agents": true}
	if len(c.Metrics) != len(want) {
		t.Errorf("metrics keys = %v", keys)
	}
	for k := range want {
		if _, ok := c.Metrics[k]; !ok {
			t.Errorf("missing ranking-independent metric %s", k)
		}
	}
	if len(c.HostsArchived) != 1 || !reflect.DeepEqual(c.HostsArchived[0].Contribution, map[string]int{"total_open_findings": 4}) {
		t.Errorf("archived = %+v", c.HostsArchived)
	}
}

func TestCompareHostsAddedAndArchived(t *testing.T) {
	kept := HostSummary{ID: "h1", Name: "web-1", PatchNow: 1, TotalOpenFindings: 3}
	prev := snap(Headline{}, kept,
		HostSummary{ID: "h9", Name: "old", WhenConvenient: 1, RebootRequired: true, TotalOpenFindings: 2})
	cur := snap(Headline{}, kept,
		HostSummary{ID: "h3", Name: "web-4", PatchNow: 1, PatchThisWeek: 2, ImagesToUpdate: 1, NoFixFindings: 6, TotalOpenFindings: 9},
		HostSummary{ID: "h2", Name: "clean"})
	c := Compare(&prev, "r", cur)
	wantAdded := []HostChange{
		{ID: "h2", Name: "clean", Contribution: map[string]int{}},
		{ID: "h3", Name: "web-4", Contribution: map[string]int{
			"patch_now": 1, "patch_this_week": 2, "images_to_update": 1, "no_fix_findings": 6, "total_open_findings": 9,
		}},
	}
	if !reflect.DeepEqual(c.HostsAdded, wantAdded) {
		t.Errorf("added = %+v", c.HostsAdded)
	}
	wantArchived := []HostChange{{ID: "h9", Name: "old", Contribution: map[string]int{
		"when_convenient": 1, "reboots_required": 1, "total_open_findings": 2,
	}}}
	if !reflect.DeepEqual(c.HostsArchived, wantArchived) {
		t.Errorf("archived = %+v", c.HostsArchived)
	}
	assertNoNilLists(t, c)
}

func deref(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}
