package email

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/pippinmole/upkeep.sh/server/internal/notify"
	"github.com/pippinmole/upkeep.sh/server/internal/reports"
)

// Until the HTML report lands, a report email is the plain-text headline
// with the report link.
func TestRenderReportPlainText(t *testing.T) {
	raw, err := os.ReadFile("../../../../web/src/lib/report-snapshot.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var s reports.Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	m := Render(notify.Notification{
		Kind: notify.KindReport, Summary: reports.Title(s), Events: []notify.Event{},
		Report: &notify.Report{ID: "r-1", URL: "https://upkeep.example/dashboard/reports/r-1", Snapshot: &s},
	})
	// Same subject as web/src/lib/report-summary.ts reportEmailSubject.
	if SubjectPrefix+m.Subject != "[upkeep.sh] Monday patch list: 1 urgent action, 2 to patch this week, 1 image to update, 1 host not reporting" {
		t.Errorf("subject %q", m.Subject)
	}
	for _, want := range []string{"Open findings: 42 (+12, +40%)", "Open in upkeep.sh: https://upkeep.example/dashboard/reports/r-1", "Notification settings"} {
		if !strings.Contains(m.Body, want) {
			t.Errorf("body lacks %q:\n%s", want, m.Body)
		}
	}
}
