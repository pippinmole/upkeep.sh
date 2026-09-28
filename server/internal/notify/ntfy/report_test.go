package ntfy

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/pippinmole/upkeep.sh/server/internal/notify"
	"github.com/pippinmole/upkeep.sh/server/internal/reports"
)

// The shared snapshot fixture (see internal/reports/snapshot_test.go).
const exampleFile = "../../../../web/src/lib/report-snapshot.example.json"

func reportNotification(t *testing.T) (notify.Notification, *reports.Snapshot) {
	t.Helper()
	raw, err := os.ReadFile(exampleFile)
	if err != nil {
		t.Fatal(err)
	}
	var s reports.Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	return notify.Notification{
		Version: notify.PayloadVersion, ID: "n-1", DeliveryID: "d-1", Kind: notify.KindReport,
		Summary: reports.Title(s), Events: []notify.Event{},
		Report: &notify.Report{ID: "r-1", URL: "https://upkeep.example/dashboard/reports/r-1", Snapshot: &s},
	}, &s
}

func TestRenderReport(t *testing.T) {
	n, snap := reportNotification(t)
	m := Render("topic", "", n)
	if m.Title != "Monday patch list: 1 urgent action, 2 to patch this week, 1 image to update, 1 host not reporting" {
		t.Errorf("title %q", m.Title)
	}
	// The fixture has a KEV action: priority 4, not 5 (a report never pages).
	if m.Priority != PriorityHigh || !slices.Equal(m.Tags, []string{"clipboard", "kev"}) {
		t.Errorf("priority %d, tags %v", m.Priority, m.Tags)
	}
	if m.Click != n.Report.URL || m.Topic != "topic" {
		t.Errorf("click %q topic %q", m.Click, m.Topic)
	}
	for _, want := range []string{
		"Estate: 4 hosts, 7 containers, 3 images\n",
		"Patch now (KEV): 1 (+1)\n",
		"Patch this week: 2 (no change)\n",
		"No fix available yet: 14 (+2, +16.7%)\n",
		"Open findings: 42 (+12, +40%)\n",
		"Resolved since last report: 3 (-3)\n",
		"Changes since the previous report of 2026-09-21.",
	} {
		if !strings.Contains(m.Message, want) {
			t.Errorf("body lacks %q:\n%s", want, m.Message)
		}
	}
	if len(m.Message) > maxMessage || strings.Contains(m.Message, "Rule:") {
		t.Errorf("body (%d bytes):\n%s", len(m.Message), m.Message)
	}

	// Nothing to patch now: default priority, no kev tag.
	snap.Headline.PatchNow = 0
	if m := Render("topic", "auto", n); m.Priority != PriorityDefault || !slices.Equal(m.Tags, []string{"clipboard"}) {
		t.Errorf("no KEV: priority %d, tags %v", m.Priority, m.Tags)
	}
	// A channel's fixed priority wins.
	snap.Headline.PatchNow = 1
	if m := Render("topic", "2", n); m.Priority != 2 {
		t.Errorf("fixed priority: %d", m.Priority)
	}
	// First report: numbers without changes; no link without SW_DASHBOARD_URL.
	snap.Changes = nil
	n.Report.URL = ""
	m = Render("topic", "", n)
	if !strings.Contains(m.Message, "Open findings: 42\n") || !strings.Contains(m.Message, "First report of this schedule") || m.Click != "" {
		t.Errorf("first report:\n%s (click %q)", m.Message, m.Click)
	}
	// A ranking change: only the metrics Compare kept get a change.
	snap.Changes = &reports.Changes{Comparable: false, Metrics: map[string]reports.MetricChange{
		"total_open_findings": {Previous: 40, Current: 42, Delta: 2},
	}}
	m = Render("topic", "", n)
	if !strings.Contains(m.Message, "Patch now (KEV): 1\n") || !strings.Contains(m.Message, "Open findings: 42 (+2)\n") ||
		!strings.Contains(m.Message, "ranking rules changed") {
		t.Errorf("not comparable:\n%s", m.Message)
	}
}
