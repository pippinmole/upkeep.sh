package findings

import (
	"reflect"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/severity"
)

func TestBuildImageKeysAndKernels(t *testing.T) {
	img := Image{ID: "sha256:abc", OS: "linux", Arch: "amd64", Refs: []string{"nginx:1.27"}, Containers: []string{"web"}}
	rows := []HostMatch{
		hm(1, "libssl3", "openssl", "3.0.11-1~deb12u2", "", "CVE-2024-1", sp("3.0.13-1~deb12u1"), "standard", "medium"),
		hm(2, "openssl", "openssl", "3.0.11-1~deb12u2", "", "CVE-2024-1", sp("3.0.13-1~deb12u1"), "standard", "medium"),
		// A kernel image shipped inside a container image never runs.
		hm(3, "linux-image-6.1.0-18-amd64", "linux", "6.1.76-1", "6.1.0-18-amd64", "CVE-2024-9", sp("6.1.80-1"), "standard", "high"),
	}
	ds := BuildImage(img, rows, map[string]CVE{"CVE-2024-1": {CVSS: fp(7.5)}})
	if len(ds) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(ds), ds)
	}
	d := ds[0]
	if d.Kind != KindVulnerableImage || d.DedupKey != "img:sha256:abc:openssl:CVE-2024-1" ||
		!reflect.DeepEqual(d.SoftwareIDs, []int64{1, 2}) || d.RunningKernelUnknown {
		t.Errorf("image finding: %+v", d)
	}
	if d.Image == nil || d.Image.ID != "sha256:abc" || !reflect.DeepEqual(d.Image.Containers, []string{"web"}) {
		t.Errorf("image snapshot: %+v", d.Image)
	}

	// Host findings keep their kind and key.
	if hd := Build(rows[:1], "", nil); len(hd) != 1 || hd[0].Kind != KindVulnerablePackage || hd[0].Image != nil {
		t.Errorf("host finding: %+v", hd)
	}
}

// Host and image findings share one lifecycle: reconciled together, keyed
// apart.
func TestReconcileMixedKinds(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	img := Image{ID: "sha256:abc"}
	row := hm(1, "libssl3", "openssl", "3.0.11-1", "", "CVE-2024-1", nil, "", "low")
	desired := append(Build([]HostMatch{row}, "", nil), BuildImage(img, []HostMatch{row}, nil)...)
	existing := []Existing{
		{ID: "1", DedupKey: "img:sha256:abc:openssl:CVE-2024-1", Status: StatusResolved, FirstSeenAt: now.Add(-time.Hour), ReopenCount: 1},
		{ID: "2", DedupKey: "img:sha256:old:openssl:CVE-2024-1", Status: StatusOpen, FirstSeenAt: now.Add(-time.Hour)},
	}
	p := Reconcile(existing, desired, now)
	opened, reopened, kept, resolved := p.Counts()
	if opened != 1 || reopened != 1 || kept != 0 || resolved != 1 || !reflect.DeepEqual(p.Resolve, []string{"2"}) {
		t.Fatalf("plan: %d opened, %d reopened, %d kept, %d resolved %v", opened, reopened, kept, resolved, p.Resolve)
	}
	for _, u := range p.Upserts {
		if u.Reopened && (u.Kind != KindVulnerableImage || u.ReopenCount != 2) {
			t.Errorf("reopened image finding: %+v", u)
		}
	}
}

func TestScoreOf(t *testing.T) {
	rows := []HostMatch{
		hm(1, "libssl3", "openssl", "3.0.11-1", "", "CVE-2024-1", sp("3.0.13-1"), "standard", "medium"),
		hm(2, "openssl", "openssl", "3.0.11-1", "", "CVE-2024-1", sp("3.0.13-1"), "standard", "medium"),
		hm(3, "zlib1g", "zlib", "1.2.13-1", "", "CVE-2024-2", nil, "", "low"),
		hm(4, "libc6", "glibc", "2.36-9", "", "CVE-2024-3", nil, "", "low"),
		hm(5, "linux-image-6.1.0-18-amd64", "linux", "6.1.76-1", "6.1.0-18-amd64", "CVE-2024-9", nil, "", "high"),
	}
	sc := ScoreOf(rows, map[string]CVE{"CVE-2024-2": {KEV: true, CVSS: fp(9.8)}, "CVE-2024-3": {CVSS: fp(5.5)}})
	if sc.Vulns != 3 || sc.Worst != severity.BucketCritical || sc.KEV != 1 || sc.Fixable != 1 {
		t.Errorf("score: %+v", sc)
	}
	if sc.ByBucket[severity.BucketCritical] != 1 || sc.ByBucket[severity.BucketMedium] != 1 || sc.ByBucket[severity.BucketLow] != 1 {
		t.Errorf("buckets: %v", sc.ByBucket)
	}
	if sc.MaxCVSS == nil || *sc.MaxCVSS != 9.8 || sc.TopKey == 0 {
		t.Errorf("max cvss / top key: %v %v", sc.MaxCVSS, sc.TopKey)
	}
	if empty := ScoreOf(nil, nil); empty.Vulns != 0 || empty.Worst != 0 || empty.MaxCVSS != nil {
		t.Errorf("clean score: %+v", empty)
	}
}
