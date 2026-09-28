package reports

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// loadExample reads the shared fixture (ExampleFile).
func loadExample(t *testing.T) Snapshot {
	t.Helper()
	raw, err := os.ReadFile(ExampleFile)
	if err != nil {
		t.Fatal(err)
	}
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// Mirrors web/src/lib/report-summary.test.ts: the email subject there and
// the ntfy title here must be the same text.
func TestSummary(t *testing.T) {
	fixture := loadExample(t)
	if got, want := Summary(fixture), "1 urgent action, 2 to patch this week, 1 image to update, 1 host not reporting"; got != want {
		t.Errorf("fixture summary = %q, want %q", got, want)
	}
	if got, want := Title(fixture), "Monday patch list: 1 urgent action, 2 to patch this week, 1 image to update, 1 host not reporting"; got != want {
		t.Errorf("fixture title = %q, want %q", got, want)
	}

	with := func(h Headline, staleHosts ...[]string) Snapshot {
		s := fixture
		s.Headline = fixture.Headline
		s.Headline.PatchNow, s.Headline.PatchThisWeek, s.Headline.ImagesToUpdate, s.Headline.StaleAgents =
			h.PatchNow, h.PatchThisWeek, h.ImagesToUpdate, h.StaleAgents
		s.Coverage.StaleAgents = []StaleAgent{}
		for i, ids := range staleHosts {
			a := StaleAgent{AgentID: fmt.Sprintf("agent-%d", i), Name: fmt.Sprintf("agent-%d", i), Hosts: []HostRef{}}
			for _, id := range ids {
				a.Hosts = append(a.Hosts, HostRef{ID: id, Name: id})
			}
			s.Coverage.StaleAgents = append(s.Coverage.StaleAgents, a)
		}
		return s
	}
	for _, c := range []struct {
		name string
		s    Snapshot
		want string
	}{
		{"all clear", with(Headline{}), "all clear"},
		{"plurals and order", with(Headline{PatchNow: 2, PatchThisWeek: 1, ImagesToUpdate: 3, StaleAgents: 1}, []string{"h1", "h2"}),
			"2 urgent actions, 1 to patch this week, 3 images to update, 2 hosts not reporting"},
		{"hosts counted once across agents", with(Headline{StaleAgents: 2}, []string{"h1", "h2"}, []string{"h2"}), "2 hosts not reporting"},
		{"stale agent with no hosts", with(Headline{StaleAgents: 1}, []string{}), "1 agent not reporting"},
		{"stale agents fall back to agents", with(Headline{StaleAgents: 3}), "3 agents not reporting"},
		{"skips zero parts", with(Headline{ImagesToUpdate: 1}), "1 image to update"},
	} {
		if got := Summary(c.s); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
