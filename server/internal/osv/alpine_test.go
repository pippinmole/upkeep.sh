package osv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Alpine fixtures are real records from OSV's top-level Alpine/all.zip
// (fetched 2026-09-28), trimmed like the others: ALPINE-CVE-* ids, the
// CVE only in `upstream`, source package = apk origin, CVSS but no
// distro severity.

func TestNormalizeAlpineCVE(t *testing.T) {
	a, ok := load(t, "alpine_cve_fixed.json", "osv-alpine")
	if !ok {
		t.Fatal("record affecting 3.22/3.24 must be relevant")
	}
	// Keyed by the wrapped CVE, like DEBIAN-CVE-/UBUNTU-CVE- records, so
	// KEV/EPSS/CVSS join and the matcher treats it as per-CVE.
	if a.VulnKey != "CVE-2024-6119" || strings.Join(a.CVEIDs, ",") != "CVE-2024-6119" {
		t.Errorf("vuln_key/cve_ids = %s/%v", a.VulnKey, a.CVEIDs)
	}
	if !IsPerCVE(a.ID) {
		t.Error("ALPINE-CVE-* must be a per-CVE record")
	}
	// CVSS feeds cves; there is no distro severity to rank by.
	if !strings.HasPrefix(a.CVSSv3Vector, "CVSS:3.1/") {
		t.Errorf("cvss vector = %q", a.CVSSv3Vector)
	}
	if a.Severity != nil {
		t.Errorf("record severity = %q, want none", *a.Severity)
	}
	rows := rowsByKey(t, a)
	// 3.17-3.20 are listed but unsupported in testReleases.
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want 3.22 and 3.24 only", a.Affected)
	}
	for _, rel := range []string{"3.22", "3.24"} {
		r, ok := rows[rel+"/openssl/"+ChannelStandard]
		if !ok {
			t.Fatalf("missing %s/openssl", rel)
		}
		if r.Distro != "alpine" || r.Introduced != "3.0.0" || str(r.FixedVersion) != "3.3.2-r0" ||
			r.Status != "fixed" || r.DistroSeverity != nil || r.Ecosystem != "Alpine:v"+rel {
			t.Errorf("%s row = %+v", rel, r)
		}
	}
}

func TestNormalizeAlpineNeverAffected(t *testing.T) {
	a, ok := load(t, "alpine_cve_withdrawn.json", "osv-alpine")
	if !ok {
		t.Fatal("must be relevant (kept for reference)")
	}
	// Withdrawn: stored without affected rows, so it matches nothing.
	if a.Withdrawn == nil || len(a.Affected) != 0 {
		t.Fatalf("withdrawn=%v rows=%d", a.Withdrawn, len(a.Affected))
	}
	// Re-normalized as if not withdrawn, secdb's "fixed: 0" (never
	// affected in this branch) is not_affected, not a fix.
	rec := mustParse(t, "alpine_cve_withdrawn.json")
	rec.Withdrawn = ""
	a, _, err := Normalize(rec, "osv-alpine", testReleases)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Affected) != 2 {
		t.Fatalf("rows = %+v", a.Affected)
	}
	for _, r := range a.Affected {
		if r.Status != "not_affected" {
			t.Errorf("row %+v: status %s, want not_affected", r, r.Status)
		}
	}
}

func mustParse(t *testing.T, name string) *Record {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// Every supported Alpine branch's feed is imported, the rest skipped.
func TestAlpineReleaseLookup(t *testing.T) {
	for eco, want := range map[string]bool{
		"Alpine:v3.22": true, "Alpine:v3.24": true, "Alpine:v3.20": false, "Alpine:v3.25": false,
	} {
		rel, ch, ok := testReleases.Lookup(eco)
		if ok != want || (ok && (rel.Codename != eco[len("Alpine:v"):] || ch != ChannelStandard)) {
			t.Errorf("Lookup(%s) = %+v %s %v", eco, rel, ch, ok)
		}
	}
	// Fingerprints are per distro: Alpine rows don't change Debian's.
	deb := NewReleases([]Release{{"debian", "bookworm", "12", true}})
	both := NewReleases([]Release{{"debian", "bookworm", "12", true}, {"alpine", "3.22", "3.22", true}})
	if deb.Fingerprint("debian") != both.Fingerprint("debian") || both.Fingerprint("alpine") == both.Fingerprint("debian") {
		t.Error("fingerprint must be scoped to one distro")
	}
}
