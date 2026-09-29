package matcher

import (
	"strings"
	"testing"
)

func TestAssessed(t *testing.T) {
	tests := []struct {
		eco, distro, release string
		supported            bool
		want                 bool
	}{
		{"deb", "debian", "bookworm", true, true},
		{"deb", "ubuntu", "jammy", true, true},
		{"apk", "alpine", "3.22", true, true},
		{"deb", "debian", "buster", false, false}, // out of support: advisories not imported
		{"deb", "debian", "sid", false, false},    // not in distro_releases
		{"apk", "alpine", "3.18", false, false},
		{"deb", "debian", "", true, false},   // release unknown: can't join per-release advisories
		{"apk", "debian", "12", true, false}, // apk packages in a non-Alpine image
		{"deb", "alpine", "3.22", true, false},
		{"rpm", "rhel", "9", true, false},
		{"npm", "", "", false, true}, // language: no distro, release ignored
		{"npm", "", "", true, true},
		{"npm", "debian", "12", true, false}, // language packages are never distro-scoped
		{"pypi", "", "", false, true},
		{"gem", "", "", false, false},
		{"homebrew", "", "", false, false},
	}
	for _, tt := range tests {
		if got := Assessed(tt.eco, tt.distro, tt.release, tt.supported); got != tt.want {
			t.Errorf("Assessed(%q, %q, %q, %v) = %v, want %v", tt.eco, tt.distro, tt.release, tt.supported, got, tt.want)
		}
	}
}

func TestReleaseStatusOf(t *testing.T) {
	yes, no := true, false
	if ReleaseStatusOf(&yes) != ReleaseSupported || ReleaseStatusOf(&no) != ReleaseOutOfSupport ||
		ReleaseStatusOf(nil) != ReleaseUnknown {
		t.Error("ReleaseStatusOf")
	}
}

// alpineCVE builds an ALPINE-CVE-* row (per-CVE, standard channel).
func alpineCVE(cve, introduced string, fixed *string) Row {
	r := Row{AdvisoryID: "ALPINE-" + cve, VulnKey: cve, CVEIDs: []string{cve}, Channel: ChannelStandard,
		Introduced: introduced, Fixed: fixed, Status: "unfixed"}
	if fixed != nil {
		r.Status = "fixed"
	}
	return r
}

// The apk comparator decides, not dpkg's: these differ between the two.
func TestEvaluateApk(t *testing.T) {
	apk, ok := ComparatorFor("apk")
	if !ok {
		t.Fatal("apk not registered")
	}
	const cve = "CVE-2024-6119"
	tests := []struct {
		name, v string
		row     Row
		want    bool
	}{
		{"below fix", "3.3.1-r0", alpineCVE(cve, "0", sp("3.3.2-r0")), true},
		{"at fix", "3.3.2-r0", alpineCVE(cve, "0", sp("3.3.2-r0")), false},
		{"revision above fix", "3.3.2-r1", alpineCVE(cve, "0", sp("3.3.2-r0")), false},
		{"revision below fix", "3.3.2-r9", alpineCVE(cve, "0", sp("3.3.2-r10")), true},
		{"upstream-only introduced covers -r0", "3.0.0-r0", alpineCVE(cve, "3.0.0", sp("3.0.15-r0")), true},
		{"below introduced", "1.1.1w-r1", alpineCVE(cve, "3.0.0", sp("3.0.15-r0")), false},
		{"upstream-only fixed", "7.51.0-r0", alpineCVE(cve, "0", sp("7.51.0")), false},
		{"release after rc fix", "2.0-r0", alpineCVE(cve, "0", sp("2.0_rc1-r0")), false},
		{"rc before release fix", "2.0_rc1-r0", alpineCVE(cve, "0", sp("2.0-r0")), true},
		{"_p after release", "9.6_p1-r0", alpineCVE(cve, "0", sp("9.6-r3")), false},
		{"unfixed", "1.0-r0", alpineCVE(cve, "0", nil), true},
	}
	for _, tt := range tests {
		ms, st := Evaluate(tt.v, apk, []Row{tt.row})
		if st.BadVersions != 0 {
			t.Errorf("%s: bad versions %d", tt.name, st.BadVersions)
		}
		if got := len(ms) == 1; got != tt.want {
			t.Errorf("%s: matched = %v, want %v (%+v)", tt.name, got, tt.want, ms)
		}
	}

	// An invalid advisory version is counted and skipped, never guessed.
	ms, st := Evaluate("1.0-r0", apk, []Row{alpineCVE(cve, "0", sp("1999-12-14"))})
	if len(ms) != 0 || st.BadVersions != 1 {
		t.Errorf("invalid fixed: %+v %+v", ms, st)
	}

	// The highest fix by apk ordering, not text.
	ms, _ = Evaluate("1.0-r0", apk, []Row{
		alpineCVE("CVE-2024-1", "0", sp("1.0-r9")),
		alpineCVE("CVE-2024-2", "0", sp("1.0-r10")),
	})
	if f := MaxStandardFix(apk, ms); f == nil || *f != "1.0-r10" {
		t.Errorf("MaxStandardFix = %v", f)
	}
}

// langRow builds a language advisory row (GHSA-/PYSEC-/GO-, keyed like a
// notice: by its CVE aliases, else vulnKey).
func langRow(id, vulnKey string, cves []string, introduced string, fixed, last *string) Row {
	r := Row{AdvisoryID: id, VulnKey: vulnKey, CVEIDs: cves, Channel: ChannelStandard,
		Introduced: introduced, Fixed: fixed, LastAffected: last, Status: "unfixed"}
	if fixed != nil {
		r.Status = "fixed"
	}
	return r
}

func TestAdvisoryScope(t *testing.T) {
	if d, r := AdvisoryScope("npm", "", ""); d != "" || r != "npm" {
		t.Errorf("npm scope = %q/%q", d, r)
	}
	if d, r := AdvisoryScope("deb", "debian", "bookworm"); d != "debian" || r != "bookworm" {
		t.Errorf("deb scope = %q/%q", d, r)
	}
	if !Language("npm") || Language("deb") || Language("gem") {
		t.Error("Language")
	}
}

// Language ecosystems combine ranges as OSV does: affected if any range
// (of any record for the key) contains the version.
func TestEvaluateNpmRanges(t *testing.T) {
	npm, ok := ComparatorFor("npm")
	if !ok {
		t.Fatal("npm not registered")
	}
	const cve = "CVE-2021-23337"
	ghsa := "GHSA-35jh-r3h4-6jhm"
	// One record, two branches: [0, 3.10.2) and [4.0.0, 4.17.21).
	branches := []Row{
		langRow(ghsa, cve, []string{cve}, "0", sp("3.10.2"), nil),
		langRow(ghsa, cve, []string{cve}, "4.0.0", sp("4.17.21"), nil),
	}
	tests := []struct {
		v       string
		rows    []Row
		wantFix string // "" = not matched, "-" = matched without a fix
	}{
		{"3.10.1", branches, "3.10.2"},
		{"3.10.2", branches, ""},
		{"4.17.20", branches, "4.17.21"}, // the distro rule would call it fixed (>= 3.10.2)
		{"4.17.21", branches, ""},
		{"4.17.21-rc.1", branches, "4.17.21"}, // prerelease sorts below the release
		{"5.0.0", branches, ""},
		// last_affected: inclusive, no fix known.
		{"1.2.3", []Row{langRow(ghsa, cve, []string{cve}, "0", nil, sp("1.2.3"))}, "-"},
		{"1.2.4", []Row{langRow(ghsa, cve, []string{cve}, "0", nil, sp("1.2.3"))}, ""},
		// An explicit versions list: one exact row per version.
		{"2.0.0", []Row{langRow(ghsa, cve, []string{cve}, "2.0.0", nil, sp("2.0.0"))}, "-"},
		{"2.0.1", []Row{langRow(ghsa, cve, []string{cve}, "2.0.0", nil, sp("2.0.0"))}, ""},
		// Two records for one CVE that disagree: the union, lowest fix of
		// the rows containing v.
		{"1.5.0", []Row{
			langRow(ghsa, cve, []string{cve}, "0", sp("1.4.0"), nil),
			langRow("GHSA-xxxx-yyyy-zzzz", cve, []string{cve}, "1.0.0", sp("1.6.0"), nil),
		}, "1.6.0"},
	}
	for _, tt := range tests {
		ms, st := Evaluate(tt.v, npm, tt.rows)
		if st.BadVersions != 0 {
			t.Errorf("%s: bad versions %d", tt.v, st.BadVersions)
		}
		switch {
		case tt.wantFix == "" && len(ms) != 0:
			t.Errorf("%s: matched %+v, want none", tt.v, ms)
		case tt.wantFix != "" && len(ms) != 1:
			t.Errorf("%s: %d matches, want 1", tt.v, len(ms))
		case tt.wantFix == "-" && ms[0].FixedVersion != nil:
			t.Errorf("%s: fix %q, want none", tt.v, *ms[0].FixedVersion)
		case tt.wantFix != "" && tt.wantFix != "-" && (ms[0].FixedVersion == nil || *ms[0].FixedVersion != tt.wantFix):
			t.Errorf("%s: fix %v, want %s", tt.v, ms[0].FixedVersion, tt.wantFix)
		case len(ms) == 1 && ms[0].VulnKey != cve:
			t.Errorf("%s: key %s", tt.v, ms[0].VulnKey)
		}
	}

	// A GHSA without a CVE keys by its (GHSA) vuln_key.
	ms, _ := Evaluate("1.0.0", npm, []Row{langRow(ghsa, ghsa, nil, "0", sp("1.0.1"), nil)})
	if len(ms) != 1 || ms[0].VulnKey != ghsa || strings.Join(ms[0].AdvisoryIDs, ",") != ghsa {
		t.Errorf("GHSA-only: %+v", ms)
	}
	// An invalid range version is counted and skipped.
	ms, st := Evaluate("1.0.0", npm, []Row{langRow(ghsa, cve, []string{cve}, "0", sp("1.0"), nil)})
	if len(ms) != 0 || st.BadVersions != 1 {
		t.Errorf("invalid fixed: %+v %+v", ms, st)
	}
}

// PyPI: PEP 440 ordering, and a GHSA plus a PYSEC record for one CVE
// giving one match that cites both.
func TestEvaluatePyPI(t *testing.T) {
	py, ok := ComparatorFor("pypi")
	if !ok {
		t.Fatal("pypi not registered")
	}
	const cve = "CVE-2025-27516"
	rows := []Row{
		langRow("GHSA-cpwx-vrp4-4pq7", cve, []string{cve}, "0", sp("3.1.6"), nil),
		langRow("PYSEC-2026-1471", cve, []string{cve}, "0", sp("3.1.6"), nil),
	}
	for _, tt := range []struct {
		v    string
		want bool
	}{
		{"3.1.5", true}, {"3.1.6rc1", true}, {"3.1.6.dev0", true}, {"3.1.6", false},
		{"3.1.6.post1", false}, {"3.1.6+local", false}, {"3.1.10", false}, {"3.1", true},
	} {
		ms, st := Evaluate(tt.v, py, rows)
		if st.BadVersions != 0 || (len(ms) == 1) != tt.want {
			t.Errorf("%s: %+v %+v, want matched=%v", tt.v, ms, st, tt.want)
			continue
		}
		if tt.want && (ms[0].VulnKey != cve || strings.Join(ms[0].AdvisoryIDs, ",") != "GHSA-cpwx-vrp4-4pq7,PYSEC-2026-1471" ||
			*ms[0].FixedVersion != "3.1.6") {
			t.Errorf("%s: %+v", tt.v, ms[0])
		}
	}
	// A legacy (non-PEP 440) installed version is invalid, never guessed.
	if py.Validate("0.1.0.dev-120828c") == nil {
		t.Error("legacy version accepted")
	}
}
