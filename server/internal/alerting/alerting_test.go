package alerting

import (
	"strings"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/notify"
)

func ip(n int) *int { return &n }

func TestMatch(t *testing.T) {
	base := Rule{ID: "r", UserID: "u", EventTypes: []string{notify.EventFindingOpened, notify.EventAgentStale}}
	opened := EventMeta{UserID: "u", Type: notify.EventFindingOpened, HostIDs: []string{"h1"}, SeverityRank: ip(4)}
	stale := EventMeta{UserID: "u", Type: notify.EventAgentStale, HostIDs: []string{"h1", "h2"}}

	with := func(f func(*Rule)) Rule { r := base; f(&r); return r }
	cases := []struct {
		name string
		rule Rule
		ev   EventMeta
		want bool
	}{
		{"type selected", base, opened, true},
		{"type not selected", base, EventMeta{UserID: "u", Type: notify.EventFindingResolved, SeverityRank: ip(6)}, false},
		{"other user", base, EventMeta{UserID: "v", Type: notify.EventFindingOpened, SeverityRank: ip(6)}, false},
		{"severity floor met", with(func(r *Rule) { r.MinSeverityRank = 4 }), opened, true},
		{"severity below floor", with(func(r *Rule) { r.MinSeverityRank = 5 }), opened, false},
		{"severity unknown with floor", with(func(r *Rule) { r.MinSeverityRank = 1 }),
			EventMeta{UserID: "u", Type: notify.EventFindingOpened}, false},
		{"kev only, not kev", with(func(r *Rule) { r.KEVOnly = true }), opened, false},
		{"kev only, kev", with(func(r *Rule) { r.KEVOnly = true }),
			EventMeta{UserID: "u", Type: notify.EventFindingOpened, KEV: true, SeverityRank: ip(6)}, true},
		{"severity/kev don't apply to agent events", with(func(r *Rule) { r.MinSeverityRank = 6; r.KEVOnly = true }), stale, true},
		{"host scope hit", with(func(r *Rule) { r.HostIDs = []string{"h1"} }), opened, true},
		{"host scope miss", with(func(r *Rule) { r.HostIDs = []string{"h9"} }), opened, false},
		{"host scope, agent with a selected host", with(func(r *Rule) { r.HostIDs = []string{"h2"} }), stale, true},
		{"host scope, event without hosts", with(func(r *Rule) { r.HostIDs = []string{"h1"} }),
			EventMeta{UserID: "u", Type: notify.EventAgentStale}, false},
		{"empty (non-nil) scope matches nothing", with(func(r *Rule) { r.HostIDs = []string{} }), opened, false},
		{"finding kind selected", with(func(r *Rule) { r.FindingKinds = []string{"vulnerable_image"} }),
			EventMeta{UserID: "u", Type: notify.EventFindingOpened, FindingKind: "vulnerable_image"}, true},
		{"finding kind not selected", with(func(r *Rule) { r.FindingKinds = []string{"vulnerable_package"} }),
			EventMeta{UserID: "u", Type: notify.EventFindingOpened, FindingKind: "vulnerable_image"}, false},
		{"finding kind unknown on the event", with(func(r *Rule) { r.FindingKinds = []string{"vulnerable_package"} }),
			opened, true},
		{"finding kinds don't apply to agent events", with(func(r *Rule) { r.FindingKinds = []string{"vulnerable_image"} }),
			stale, true},
	}
	for _, c := range cases {
		if got := Match(c.rule, c.ev); got != c.want {
			t.Errorf("%s: Match = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDedup(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	if Suppressed(nil, time.Hour, now) {
		t.Error("never sent is suppressed")
	}
	if !Suppressed(at(30*time.Minute), time.Hour, now) {
		t.Error("inside window not suppressed")
	}
	if Suppressed(at(time.Hour), time.Hour, now) || Suppressed(at(2*time.Hour), time.Hour, now) {
		t.Error("window end is exclusive")
	}
	if Suppressed(at(time.Second), 0, now) {
		t.Error("window 0 disables dedup")
	}
	a := EventMeta{Type: notify.EventFindingOpened, Subject: "finding:h:pkg:x:CVE-1"}
	b := EventMeta{Type: notify.EventFindingResolved, Subject: a.Subject}
	if DedupKey(a) == DedupKey(b) {
		t.Error("opened and resolved of one finding must not dedup each other")
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
	f := func(typ, sev string, kev bool, host *notify.Host) notify.Event {
		return notify.Event{Type: typ, Host: host, Finding: &notify.Finding{VulnKey: "CVE-1", SourcePackage: "openssl", Severity: sev, KEV: kev}}
	}
	if s := Summary(notify.KindAlert, []notify.Event{f(notify.EventFindingOpened, "critical", true, h)}); s != "New finding CVE-1 in openssl on web-1 (critical, KEV)" {
		t.Errorf("single: %q", s)
	}
	s := Summary(notify.KindDigest, []notify.Event{
		f(notify.EventFindingOpened, "critical", true, h),
		f(notify.EventFindingOpened, "high", false, h),
		f(notify.EventFindingResolved, "critical", true, h),
	})
	if s != "Digest: 2 new, 1 resolved findings on web-1 (1 critical, 1 KEV)" {
		t.Errorf("digest: %q", s)
	}
	s = Summary(notify.KindAlert, []notify.Event{
		f(notify.EventFindingOpened, "low", false, h),
		f(notify.EventFindingOpened, "low", false, &notify.Host{Hostname: "db-1"}),
	})
	if s != "2 new findings across 2 hosts" {
		t.Errorf("multi-host: %q", s)
	}
	s = Summary(notify.KindAlert, []notify.Event{{Type: notify.EventAgentStale, Agent: &notify.Agent{Name: "a1"}}})
	if s != `Agent "a1" stopped reporting` {
		t.Errorf("agent: %q", s)
	}
	s = Summary(notify.KindAlert, []notify.Event{
		{Type: notify.EventAgentStale, Agent: &notify.Agent{Name: "a1"}},
		f(notify.EventFindingOpened, "low", false, h),
	})
	if !strings.HasPrefix(s, "1 new, 1 agent stale") || strings.Contains(s, "findings") {
		t.Errorf("mixed: %q", s)
	}
	if Summary(notify.KindTest, nil) == "" {
		t.Error("test summary")
	}
}
