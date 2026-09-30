package alerting

import (
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/notify"
)

func TestSends(t *testing.T) {
	r := Rule{NotifyOnResolve: false}
	if !r.Sends(notify.EventAlertFiring) || r.Sends(notify.EventAlertResolved) {
		t.Error("without notify_on_resolve")
	}
	r.NotifyOnResolve = true
	if !r.Sends(notify.EventAlertResolved) || r.Sends("finding.opened") {
		t.Error("with notify_on_resolve")
	}
}

func TestDigestDue(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := Rule{Digest: true, DigestInterval: time.Hour, CreatedAt: created}
	if DigestDue(r, created.Add(59*time.Minute)) {
		t.Error("due before the first interval")
	}
	if !DigestDue(r, created.Add(time.Hour)) {
		t.Error("not due after the first interval")
	}
	last := created.Add(5 * time.Hour)
	r.LastDigestAt = &last
	if DigestDue(r, last.Add(30*time.Minute)) || !DigestDue(r, last.Add(61*time.Minute)) {
		t.Error("interval not measured from the last digest")
	}
	r.Digest = false
	if !DigestDue(r, last) {
		t.Error("a rule switched to immediate must flush at once")
	}
}

func TestChunk(t *testing.T) {
	ev := make([]int, 2*MaxEventsPerNotification+1)
	for i := range ev {
		ev[i] = i
	}
	c := Chunk(ev)
	if len(c) != 3 || len(c[0]) != MaxEventsPerNotification || len(c[2]) != 1 || c[2][0] != len(ev)-1 {
		t.Fatalf("chunks %d", len(c))
	}
	if Chunk([]int{}) != nil {
		t.Fatal("empty input")
	}
}

func TestSummary(t *testing.T) {
	h := &notify.Host{Hostname: "web-1"}
	port := func(typ string, host *notify.Host) notify.Event {
		return notify.Event{Type: typ, Host: host, Alert: &notify.Alert{Title: "Port 22/tcp is listening"}}
	}
	vuln := func(sev string, kev bool) notify.Event {
		return notify.Event{Type: notify.EventAlertFiring, Host: h,
			Alert:   &notify.Alert{Title: VulnTitle("CVE-1", "openssl", sev, kev, "")},
			Finding: &notify.Finding{VulnKey: "CVE-1", Severity: sev, KEV: kev}}
	}
	cases := []struct {
		kind   string
		events []notify.Event
		want   string
	}{
		{notify.KindAlert, []notify.Event{port(notify.EventAlertFiring, h)}, "Port 22/tcp is listening on web-1"},
		{notify.KindAlert, []notify.Event{port(notify.EventAlertResolved, h)}, "Resolved: Port 22/tcp is listening on web-1"},
		{notify.KindAlert, []notify.Event{vuln("critical", true)}, "KEV CVE-1 in openssl on web-1"},
		{notify.KindDigest, []notify.Event{vuln("critical", true), vuln("high", false), port(notify.EventAlertResolved, h)},
			"Digest: 2 firing, 1 resolved alerts on web-1 (1 critical, 1 KEV)"},
		{notify.KindAlert, []notify.Event{port(notify.EventAlertFiring, h), port(notify.EventAlertFiring, &notify.Host{Hostname: "db-1"})},
			"2 firing alerts across 2 hosts"},
		{notify.KindTest, nil, "Test notification from upkeep.sh"},
		{notify.KindAlert, nil, "No events"},
	}
	for _, c := range cases {
		if got := Summary(c.kind, c.events); got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}
