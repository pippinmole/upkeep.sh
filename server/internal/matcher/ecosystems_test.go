package matcher

import "testing"

func TestAssessed(t *testing.T) {
	tests := []struct {
		eco, distro, release string
		want                 bool
	}{
		{"deb", "debian", "bookworm", true},
		{"deb", "ubuntu", "jammy", true},
		{"apk", "alpine", "3.22", true},
		{"deb", "debian", "", false},   // release unknown: can't join per-release advisories
		{"apk", "debian", "12", false}, // apk packages in a non-Alpine image
		{"deb", "alpine", "3.22", false},
		{"rpm", "rhel", "9", false},
		{"npm", "", "", false}, // task G
		{"homebrew", "", "", false},
	}
	for _, tt := range tests {
		if got := Assessed(tt.eco, tt.distro, tt.release); got != tt.want {
			t.Errorf("Assessed(%q, %q, %q) = %v, want %v", tt.eco, tt.distro, tt.release, got, tt.want)
		}
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
