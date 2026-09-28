package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/notify"
	"github.com/pippinmole/upkeep.sh/server/internal/reports"
)

// The shared snapshot fixture (see internal/reports/snapshot_test.go).
const exampleFile = "../../../../web/src/lib/report-snapshot.example.json"

// A report notification is the usual signed envelope with kind "report",
// no events, and "report": {id, url, snapshot} carrying the full stored
// snapshot unchanged.
func TestSendReport(t *testing.T) {
	raw, err := os.ReadFile(exampleFile)
	if err != nil {
		t.Fatal(err)
	}
	var snap reports.Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatal(err)
	}
	var body []byte
	var headers http.Header
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		headers = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n := New(tlsGuard(srv))
	n.Now = func() time.Time { return time.Unix(1790582404, 0) }
	note := notify.Notification{
		Version: notify.PayloadVersion, ID: "n-1", DeliveryID: "d-1", Kind: notify.KindReport,
		CreatedAt: snap.GeneratedAt, Summary: reports.Title(snap), Events: []notify.Event{},
		Report: &notify.Report{ID: "r-1", URL: "https://upkeep.example/dashboard/reports/r-1", Snapshot: &snap},
	}
	if _, err := n.Send(context.Background(), notify.Config{"url": srv.URL, "secret": "whsec_abc"}, note); err != nil {
		t.Fatal(err)
	}
	if headers.Get(HeaderKind) != "report" {
		t.Errorf("kind header %q", headers.Get(HeaderKind))
	}
	if err := Verify("whsec_abc", headers.Get(HeaderSignature), headers.Get(HeaderTimestamp), body,
		time.Unix(1790582404, 0), 5*time.Minute); err != nil {
		t.Fatalf("signature: %v", err)
	}
	var got struct {
		Version int             `json:"version"`
		Kind    string          `json:"kind"`
		Rule    *notify.RuleRef `json:"rule"`
		Summary string          `json:"summary"`
		Events  []notify.Event  `json:"events"`
		Report  struct {
			ID       string          `json:"id"`
			URL      string          `json:"url"`
			Snapshot json.RawMessage `json:"snapshot"`
		} `json:"report"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 || got.Kind != "report" || got.Rule != nil || got.Events == nil || len(got.Events) != 0 ||
		got.Summary != "Monday patch list: 1 urgent action, 2 to patch this week, 1 image to update, 1 host not reporting" ||
		got.Report.ID != "r-1" || got.Report.URL != "https://upkeep.example/dashboard/reports/r-1" {
		t.Fatalf("envelope: %s", body)
	}
	var want, sent any
	_ = json.Unmarshal(raw, &want)
	_ = json.Unmarshal(got.Report.Snapshot, &sent)
	if !reflect.DeepEqual(want, sent) {
		t.Fatalf("snapshot differs from the fixture: %s", got.Report.Snapshot)
	}

	// Without SW_DASHBOARD_URL there is no url key at all.
	note.Report.URL = ""
	b, _ := json.Marshal(note)
	if bytes.Contains(b, []byte(`"url"`)) {
		t.Errorf("url present without a dashboard URL: %s", b)
	}
}
