package findings

import (
	"reflect"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/matcher"
	"github.com/pippinmole/upkeep.sh/server/internal/severity"
)

func sp(s string) *string   { return &s }
func fp(f float64) *float64 { return &f }

func hm(id int64, pkg, src, ver, kernel, cve string, fixed *string, channel, sev string) HostMatch {
	m := matcher.Match{VulnKey: cve, AdvisoryIDs: []string{"UBUNTU-" + cve}, FixedVersion: fixed, FixChannel: channel}
	if fixed != nil {
		m.FixAdvisoryID = "UBUNTU-" + cve
	}
	if sev != "" {
		m.Severity = sp(sev)
	}
	return HostMatch{SoftwareID: id, Package: pkg, Source: src, Version: ver, KernelRelease: kernel, Match: m}
}

func TestBuildGroupsBinariesBySource(t *testing.T) {
	rows := []HostMatch{
		hm(1, "libssl3", "openssl", "3.0.2-0ubuntu1.15", "", "CVE-2024-1", sp("3.0.2-0ubuntu1.16"), "standard", "medium"),
		hm(2, "openssl", "openssl", "3.0.2-0ubuntu1.15", "", "CVE-2024-1", sp("3.0.2-0ubuntu1.16"), "standard", "medium"),
		// A lagging binary of the same source at an older version decides
		// the installed/fixed-in shown.
		hm(3, "libssl-dev", "openssl", "3.0.2-0ubuntu1.9", "", "CVE-2024-1", sp("3.0.2-0ubuntu1.16"), "standard", "medium"),
		hm(1, "libssl3", "openssl", "3.0.2-0ubuntu1.15", "", "CVE-2024-2", nil, "", "low"),
	}
	ds := Build(rows, "5.15.0-91-generic", map[string]CVE{"CVE-2024-1": {KEV: true}})
	if len(ds) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(ds), ds)
	}
	d := ds[0]
	if d.DedupKey != "pkg:openssl:CVE-2024-1" || d.InstalledVersion != "3.0.2-0ubuntu1.9" ||
		!reflect.DeepEqual(d.SoftwareIDs, []int64{1, 2, 3}) ||
		!reflect.DeepEqual(d.Packages, []string{"libssl-dev", "libssl3", "openssl"}) ||
		!reflect.DeepEqual(d.AdvisoryIDs, []string{"UBUNTU-CVE-2024-1"}) {
		t.Errorf("grouped finding: %+v", d)
	}
	if d.Severity.Bucket != severity.BucketCritical || !d.CVE.KEV {
		t.Errorf("KEV finding should be critical: %+v", d.Severity)
	}
	if ds[1].FixedVersion != nil || ds[1].Severity.Bucket != severity.BucketLow {
		t.Errorf("unfixed low finding: %+v", ds[1])
	}
}

func TestBuildRunningKernelPolicy(t *testing.T) {
	const running = "5.15.0-91-generic"
	rows := []HostMatch{
		hm(10, "linux-image-5.15.0-91-generic", "linux", "5.15.0-91.101", running, "CVE-2024-10", sp("5.15.0-92.102"), "standard", "high"),
		hm(11, "linux-modules-5.15.0-91-generic", "linux", "5.15.0-91.101", running, "CVE-2024-10", sp("5.15.0-92.102"), "standard", "high"),
		// An older installed kernel with an extra CVE the running one
		// doesn't have: informational only.
		hm(12, "linux-image-5.15.0-88-generic", "linux", "5.15.0-88.98", "5.15.0-88-generic", "CVE-2024-10", sp("5.15.0-92.102"), "standard", "high"),
		hm(12, "linux-image-5.15.0-88-generic", "linux", "5.15.0-88.98", "5.15.0-88-generic", "CVE-2024-11", sp("5.15.0-89.99"), "standard", "high"),
	}
	ds := Build(rows, running, nil)
	if len(ds) != 1 || ds[0].VulnKey != "CVE-2024-10" || ds[0].InstalledVersion != "5.15.0-91.101" ||
		!reflect.DeepEqual(ds[0].SoftwareIDs, []int64{10, 11}) || ds[0].KernelRelease != running || ds[0].RunningKernelUnknown {
		t.Fatalf("running kernel only: %+v", ds)
	}

	// Unknown running kernel: every installed kernel raises, flagged.
	ds = Build(rows, "", nil)
	if len(ds) != 2 || !ds[0].RunningKernelUnknown || !ds[1].RunningKernelUnknown {
		t.Fatalf("unknown kernel fallback: %+v", ds)
	}
	if ds[0].InstalledVersion != "5.15.0-88.98" { // lowest installed decides
		t.Errorf("installed = %s", ds[0].InstalledVersion)
	}
}

func TestProLabelAndSeverity(t *testing.T) {
	ds := Build([]HostMatch{
		hm(1, "libxmltok1", "libxmltok", "1.2-4", "", "CVE-2012-1148", sp("1.2-4ubuntu0.22.04.1~esm5"), "ubuntu-pro", "medium"),
		hm(2, "curl", "curl", "7.81.0-1", "", "CVE-2024-3", sp("7.81.0-1ubuntu1.1"), "standard", "medium"),
	}, "", map[string]CVE{"CVE-2024-3": {EPSS: fp(0.2)}})
	pro, std := ds[1], ds[0]
	if pro.VulnKey != "CVE-2012-1148" || !pro.RequiresPro() || std.RequiresPro() {
		t.Fatalf("pro labeling: %+v / %+v", pro, std)
	}
	// EPSS >= 0.10 escalates to high; fix availability counts only the
	// standard channel.
	if std.Severity.Bucket != severity.BucketHigh {
		t.Errorf("std bucket = %v", std.Severity.Bucket)
	}
	sameButStd := Assess(sp("medium"), matcher.ChannelStandard, CVE{})
	if pro.Severity.Key >= sameButStd.Key {
		t.Errorf("a Pro-only fix must not rank as 'fix available' (%d >= %d)", pro.Severity.Key, sameButStd.Key)
	}
}

// host simulates a host's current matches through several reconciles.
type host struct {
	t      *testing.T
	stored map[string]*Existing
	nextID int
}

func newHost(t *testing.T) *host { return &host{t: t, stored: map[string]*Existing{}} }

func (h *host) reconcile(at time.Time, rows ...HostMatch) Plan {
	var existing []Existing
	for _, e := range h.stored {
		existing = append(existing, *e)
	}
	p := Reconcile(existing, Build(rows, "", nil), at)
	for _, u := range p.Upserts {
		e := h.stored[u.DedupKey]
		if e == nil {
			h.nextID++
			e = &Existing{ID: string(rune('a' + h.nextID)), DedupKey: u.DedupKey}
			h.stored[u.DedupKey] = e
		}
		e.Status, e.FirstSeenAt, e.ReopenedAt, e.ReopenCount = StatusOpen, u.FirstSeenAt, u.ReopenedAt, u.ReopenCount
	}
	for _, id := range p.Resolve {
		for _, e := range h.stored {
			if e.ID == id {
				e.Status = StatusResolved
			}
		}
	}
	return p
}

func (h *host) status(key string) string {
	if e := h.stored[key]; e != nil {
		return e.Status
	}
	return ""
}

func counts(p Plan) [4]int {
	o, r, k, x := p.Counts()
	return [4]int{o, r, k, x}
}

func TestLifecycle(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	const key = "pkg:openssl:CVE-2024-1"
	vuln := hm(1, "libssl3", "openssl", "3.0.2-0ubuntu1.15", "", "CVE-2024-1", sp("3.0.2-0ubuntu1.16"), "standard", "medium")
	other := hm(5, "zlib1g", "zlib", "1:1.2.11.dfsg-2ubuntu9", "", "CVE-2022-37434", sp("1:1.2.11.dfsg-2ubuntu9.2"), "standard", "medium")
	h := newHost(t)

	// Open.
	p := h.reconcile(t0, vuln, other)
	if counts(p) != [4]int{2, 0, 0, 0} || h.status(key) != StatusOpen || !p.Upserts[0].New {
		t.Fatalf("open: %v", counts(p))
	}
	if !h.stored[key].FirstSeenAt.Equal(t0) {
		t.Errorf("first_seen_at = %v", h.stored[key].FirstSeenAt)
	}

	// Still matched: kept, first_seen unchanged.
	p = h.reconcile(t0.Add(time.Hour), vuln, other)
	if counts(p) != [4]int{0, 0, 2, 0} || !h.stored[key].FirstSeenAt.Equal(t0) {
		t.Fatalf("keep: %v", counts(p))
	}

	// Upgrade: the new openssl version has no match -> resolved.
	p = h.reconcile(t0.Add(2*time.Hour), other)
	if counts(p) != [4]int{0, 0, 1, 1} || h.status(key) != StatusResolved {
		t.Fatalf("resolve on upgrade: %v %s", counts(p), h.status(key))
	}

	// Resolved and still not matched: untouched.
	p = h.reconcile(t0.Add(3*time.Hour), other)
	if counts(p) != [4]int{0, 0, 1, 0} {
		t.Fatalf("resolved stays: %v", counts(p))
	}

	// Downgrade (or a regression advisory): reopened, first_seen kept.
	t4 := t0.Add(4 * time.Hour)
	p = h.reconcile(t4, vuln, other)
	e := h.stored[key]
	if counts(p) != [4]int{0, 1, 1, 0} || e.Status != StatusOpen || !e.FirstSeenAt.Equal(t0) ||
		e.ReopenCount != 1 || e.ReopenedAt == nil || !e.ReopenedAt.Equal(t4) {
		t.Fatalf("reopen: %v %+v", counts(p), e)
	}

	// Package removed entirely: every finding it carried resolves.
	p = h.reconcile(t0.Add(5*time.Hour), vuln)
	if counts(p) != [4]int{0, 0, 1, 1} || h.status("pkg:zlib:CVE-2022-37434") != StatusResolved {
		t.Fatalf("resolve on removal: %v", counts(p))
	}

	// Reopen again keeps counting; the reopened_at of the previous reopen
	// is carried while it stays open.
	h.reconcile(t0.Add(6*time.Hour), vuln, other)
	if h.stored["pkg:zlib:CVE-2022-37434"].ReopenCount != 1 || h.stored[key].ReopenCount != 1 ||
		!h.stored[key].ReopenedAt.Equal(t4) {
		t.Fatalf("counts after second cycle: %+v %+v", h.stored["pkg:zlib:CVE-2022-37434"], h.stored[key])
	}

	// Everything gone (e.g. host now reports an empty inventory).
	p = h.reconcile(t0.Add(7 * time.Hour))
	if counts(p) != [4]int{0, 0, 0, 2} {
		t.Fatalf("resolve all: %v", counts(p))
	}
}

func TestReconcileLeavesOtherResolvedAlone(t *testing.T) {
	now := time.Now()
	existing := []Existing{
		{ID: "1", DedupKey: "pkg:a:CVE-1", Status: StatusResolved},
		{ID: "2", DedupKey: "pkg:b:CVE-2", Status: StatusOpen},
	}
	p := Reconcile(existing, nil, now)
	if len(p.Upserts) != 0 || !reflect.DeepEqual(p.Resolve, []string{"2"}) {
		t.Errorf("plan = %+v", p)
	}
}
