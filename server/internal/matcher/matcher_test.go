package matcher

import (
	"reflect"
	"testing"
)

var deb, _ = ComparatorFor("deb")

func sp(s string) *string { return &s }

// perCVE builds a per-CVE record row (UBUNTU-CVE-*).
func perCVE(cve, channel, introduced string, fixed *string, sev string) Row {
	r := Row{AdvisoryID: "UBUNTU-" + cve, VulnKey: cve, CVEIDs: []string{cve}, Channel: channel,
		Introduced: introduced, Fixed: fixed, Status: "unfixed"}
	if fixed != nil {
		r.Status = "fixed"
	}
	if sev != "" {
		r.Severity = sp(sev)
	}
	return r
}

// notice builds a DSA/USN-style row citing cves.
func notice(id string, cves []string, channel string, fixed *string) Row {
	key := id
	if len(cves) == 1 {
		key = cves[0]
	}
	return Row{AdvisoryID: id, VulnKey: key, CVEIDs: cves, Channel: channel, Introduced: "0",
		Fixed: fixed, Status: "fixed"}
}

func eval(t *testing.T, v string, rows ...Row) []Match {
	t.Helper()
	ms, st := Evaluate(v, deb, rows)
	if st.BadVersions != 0 {
		t.Fatalf("unexpected bad versions: %d", st.BadVersions)
	}
	return ms
}

func keys(ms []Match) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.VulnKey)
	}
	return out
}

func TestPredicate(t *testing.T) {
	const cve = "CVE-2024-0001"
	tests := []struct {
		name    string
		version string
		row     Row
		want    bool
	}{
		{"below fix", "3.0.2-0ubuntu1.14", perCVE(cve, ChannelStandard, "0", sp("3.0.2-0ubuntu1.15"), ""), true},
		{"at fix", "3.0.2-0ubuntu1.15", perCVE(cve, ChannelStandard, "0", sp("3.0.2-0ubuntu1.15"), ""), false},
		{"above fix", "3.0.2-0ubuntu1.20", perCVE(cve, ChannelStandard, "0", sp("3.0.2-0ubuntu1.15"), ""), false},
		{"numeric not lexical", "3.0.2-0ubuntu1.9", perCVE(cve, ChannelStandard, "0", sp("3.0.2-0ubuntu1.10"), ""), true},
		{"unfixed", "9.9", perCVE(cve, ChannelStandard, "0", nil, ""), true},
		{"empty introduced", "1.0", perCVE(cve, ChannelStandard, "", sp("2.0"), ""), true},
		{"below introduced", "1.0-1", perCVE(cve, ChannelStandard, "1.5-1", sp("2.0-1"), ""), false},
		{"at introduced", "1.5-1", perCVE(cve, ChannelStandard, "1.5-1", sp("2.0-1"), ""), true},
		{"introduced, unfixed, above", "3.0", perCVE(cve, ChannelStandard, "1.5-1", nil, ""), true},
		// Epochs dominate: 1:1.0 > 2.0, so a fix at 2.0 doesn't apply to 1:1.0...
		{"epoch above plain fix", "1:1.0-1", perCVE(cve, ChannelStandard, "0", sp("2.0-1"), ""), false},
		// ...and a fix with an epoch is above every epoch-0 version.
		{"epoch fix above plain", "9.9-1", perCVE(cve, ChannelStandard, "0", sp("1:1.0-1"), ""), true},
		{"epoch equal compare rest", "1:1.2.11.dfsg-2ubuntu9.1", perCVE(cve, ChannelStandard, "0", sp("1:1.2.11.dfsg-2ubuntu9.2"), ""), true},
		// '~' sorts before the end of string: a backport ~deb12u1 is below
		// the unsuffixed version and above the previous one.
		{"tilde below release", "2.36-9~deb12u1", perCVE(cve, ChannelStandard, "0", sp("2.36-9"), ""), true},
		{"tilde backport fixed", "2.36-9+deb12u4", perCVE(cve, ChannelStandard, "0", sp("2.36-9+deb12u3"), ""), false},
		{"tilde rc", "1.0~rc1-1", perCVE(cve, ChannelStandard, "0", sp("1.0-1"), ""), true},
		{"ubuntu backport tilde", "12.3.0-1ubuntu1~22.04", perCVE(cve, ChannelStandard, "0", sp("12.3.0-1ubuntu1~22.04.1"), ""), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := len(eval(t, tt.version, tt.row)) == 1
			if got != tt.want {
				t.Errorf("affected(%s) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestLastAffected(t *testing.T) {
	r := Row{AdvisoryID: "DEBIAN-CVE-2024-2", VulnKey: "CVE-2024-2", CVEIDs: []string{"CVE-2024-2"},
		Channel: ChannelStandard, Introduced: "0", LastAffected: sp("1.4-2"), Status: "unfixed"}
	for v, want := range map[string]bool{"1.4-1": true, "1.4-2": true, "1.4-2+b1": false, "1.5-1": false} {
		ms := eval(t, v, r)
		if got := len(ms) == 1; got != want {
			t.Errorf("last_affected: affected(%s) = %v, want %v", v, got, want)
		}
		if len(ms) == 1 && (ms[0].FixedVersion != nil || ms[0].FixChannel != "") {
			t.Errorf("last_affected must not invent a fix: %+v", ms[0])
		}
	}
}

func TestMatchCarriesFix(t *testing.T) {
	ms := eval(t, "1.0-1", perCVE("CVE-2024-3", ChannelStandard, "0", sp("1.0-2"), "medium"))
	want := []Match{{VulnKey: "CVE-2024-3", AdvisoryIDs: []string{"UBUNTU-CVE-2024-3"},
		FixedVersion: sp("1.0-2"), FixChannel: ChannelStandard, FixAdvisoryID: "UBUNTU-CVE-2024-3", Severity: sp("medium")}}
	if !reflect.DeepEqual(ms, want) {
		t.Errorf("got %+v, want %+v", ms, want)
	}
	if MaxStandardFix(deb, ms) == nil || *MaxStandardFix(deb, ms) != "1.0-2" {
		t.Errorf("MaxStandardFix = %v", MaxStandardFix(deb, ms))
	}
}

func TestProChannel(t *testing.T) {
	const cve = "CVE-2023-9"
	std := func(fixed *string) Row { return perCVE(cve, ChannelStandard, "0", fixed, "low") }
	pro := func(fixed *string) Row { return perCVE(cve, ChannelUbuntuPro, "0", fixed, "low") }

	tests := []struct {
		name        string
		version     string
		rows        []Row
		affected    bool
		fix         string
		fixChannel  string
		requiresPro bool
	}{
		{"standard fix wins over pro fix", "1.0-1", []Row{std(sp("1.0-3")), pro(sp("1.0-1ubuntu0.1~esm1"))},
			true, "1.0-3", ChannelStandard, false},
		{"standard unfixed, pro fixed: requires pro", "1.0-1", []Row{std(nil), pro(sp("1.0-1ubuntu0.1~esm1"))},
			true, "1.0-1ubuntu0.1~esm1", ChannelUbuntuPro, true},
		{"pro-only tracking (ESM apps), fixed", "2.0-1", []Row{pro(sp("2.0-1ubuntu0.1~esm2"))},
			true, "2.0-1ubuntu0.1~esm2", ChannelUbuntuPro, true},
		{"pro-only tracking, unfixed", "2.0-1", []Row{pro(nil)}, true, "", "", false},
		{"esm build installed: fixed", "1.0-1ubuntu0.1~esm1", []Row{std(nil), pro(sp("1.0-1ubuntu0.1~esm1"))},
			false, "", "", false},
		{"standard fix installed, pro unfixed: not affected", "1.0-3", []Row{std(sp("1.0-3")), pro(nil)},
			false, "", "", false},
		{"both unfixed", "1.0-1", []Row{std(nil), pro(nil)}, true, "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := eval(t, tt.version, tt.rows...)
			if (len(ms) == 1) != tt.affected {
				t.Fatalf("affected = %v, want %v (%+v)", len(ms) == 1, tt.affected, ms)
			}
			if !tt.affected {
				return
			}
			m := ms[0]
			if got := derefS(m.FixedVersion); got != tt.fix || m.FixChannel != tt.fixChannel || m.RequiresPro() != tt.requiresPro {
				t.Errorf("fix = %q/%q pro=%v, want %q/%q pro=%v", got, m.FixChannel, m.RequiresPro(), tt.fix, tt.fixChannel, tt.requiresPro)
			}
			if tt.fix == "" && m.FixAdvisoryID != "" {
				t.Errorf("fix advisory without a fix: %+v", m)
			}
		})
	}
	if MaxStandardFix(deb, eval(t, "2.0-1", pro(sp("2.0-1ubuntu0.1~esm2")))) != nil {
		t.Error("MaxStandardFix must ignore Pro-only fixes")
	}
}

func TestPerCVERecordIsAuthoritative(t *testing.T) {
	const cve = "CVE-2024-5535"
	// The USN says fixed in .17; the per-CVE record (which follows
	// regressions) says .18. The per-CVE record decides; both are cited.
	rows := []Row{
		notice("USN-6937-1", []string{cve}, ChannelStandard, sp("3.0.2-0ubuntu1.17")),
		perCVE(cve, ChannelStandard, "0", sp("3.0.2-0ubuntu1.18"), "low"),
	}
	ms := eval(t, "3.0.2-0ubuntu1.17", rows...)
	if len(ms) != 1 || *ms[0].FixedVersion != "3.0.2-0ubuntu1.18" || ms[0].FixAdvisoryID != "UBUNTU-CVE-2024-5535" {
		t.Fatalf("got %+v", ms)
	}
	if !reflect.DeepEqual(ms[0].AdvisoryIDs, []string{"UBUNTU-CVE-2024-5535", "USN-6937-1"}) {
		t.Errorf("advisory ids = %v", ms[0].AdvisoryIDs)
	}
	// Per-CVE record says the release isn't affected here (fixed below the
	// installed version) while an older notice would still match: no match.
	if ms := eval(t, "3.0.2-0ubuntu1.18", rows...); len(ms) != 0 {
		t.Errorf("fixed per the per-CVE record, got %+v", ms)
	}
}

func TestNoticeExpandsToCVEs(t *testing.T) {
	// A multi-CVE USN with no per-CVE records for this source: one match
	// per cited CVE, not one keyed by the USN id.
	usn := notice("USN-6154-1", []string{"CVE-2023-2426", "CVE-2023-2609", "CVE-2023-2610"}, ChannelStandard, sp("2:8.2.3995-1ubuntu2.8"))
	ms := eval(t, "2:8.2.3995-1ubuntu2.7", usn)
	if got := keys(ms); !reflect.DeepEqual(got, []string{"CVE-2023-2426", "CVE-2023-2609", "CVE-2023-2610"}) {
		t.Fatalf("keys = %v", got)
	}
	for _, m := range ms {
		if *m.FixedVersion != "2:8.2.3995-1ubuntu2.8" || m.FixAdvisoryID != "USN-6154-1" {
			t.Errorf("match %+v", m)
		}
	}
	// A per-CVE record for one of them takes over that CVE only.
	ms = eval(t, "2:8.2.3995-1ubuntu2.7", usn, perCVE("CVE-2023-2609", ChannelStandard, "0", nil, "medium"))
	if len(ms) != 3 || ms[1].VulnKey != "CVE-2023-2609" || ms[1].FixedVersion != nil {
		t.Errorf("per-CVE override: %+v", ms)
	}
	// A notice citing no CVE keys by its own id.
	ms = eval(t, "1.0", Row{AdvisoryID: "DSA-9999-1", VulnKey: "DSA-9999-1", Channel: ChannelStandard, Fixed: sp("1.1"), Status: "fixed"})
	if got := keys(ms); !reflect.DeepEqual(got, []string{"DSA-9999-1"}) {
		t.Errorf("keys = %v", got)
	}
}

func TestMultipleAdvisoriesOneCVE(t *testing.T) {
	const cve = "CVE-2022-37434"
	// Two notices for one CVE (original + regression update), no per-CVE
	// record: the earliest fix resolves the CVE; later notices must not
	// reopen it.
	rows := []Row{
		notice("USN-5570-1", []string{cve}, ChannelStandard, sp("1:1.2.11.dfsg-2ubuntu9.1")),
		notice("USN-5570-2", []string{cve}, ChannelStandard, sp("1:1.2.11.dfsg-2ubuntu9.2")),
	}
	ms := eval(t, "1:1.2.11.dfsg-2ubuntu9", rows...)
	if len(ms) != 1 || *ms[0].FixedVersion != "1:1.2.11.dfsg-2ubuntu9.1" || ms[0].FixAdvisoryID != "USN-5570-1" {
		t.Fatalf("lowest fix: %+v", ms)
	}
	if !reflect.DeepEqual(ms[0].AdvisoryIDs, []string{"USN-5570-1", "USN-5570-2"}) {
		t.Errorf("advisory ids = %v", ms[0].AdvisoryIDs)
	}
	if ms := eval(t, "1:1.2.11.dfsg-2ubuntu9.1", rows...); len(ms) != 0 {
		t.Errorf("fixed by the first notice, got %+v", ms)
	}
	// Two different CVEs from different records are separate matches.
	ms = eval(t, "1.0", perCVE("CVE-2024-1", ChannelStandard, "0", nil, ""), perCVE("CVE-2024-2", ChannelStandard, "0", sp("2.0"), ""))
	if got := keys(ms); !reflect.DeepEqual(got, []string{"CVE-2024-1", "CVE-2024-2"}) {
		t.Errorf("keys = %v", got)
	}
}

func TestSeverityFallsBackToAnyAffectedRow(t *testing.T) {
	a := notice("USN-1-1", []string{"CVE-2024-7"}, ChannelStandard, sp("1.1"))
	b := notice("USN-1-2", []string{"CVE-2024-7"}, ChannelStandard, sp("1.2"))
	b.Severity = sp("high")
	ms := eval(t, "1.0", a, b)
	if len(ms) != 1 || ms[0].Severity == nil || *ms[0].Severity != "high" {
		t.Errorf("severity: %+v", ms)
	}
}

func TestSkipsBadAndNonAffectedRows(t *testing.T) {
	rows := []Row{
		perCVE("CVE-2024-8", ChannelStandard, "0", sp("not a version!"), ""),
		{AdvisoryID: "DEBIAN-CVE-2024-9", VulnKey: "CVE-2024-9", Channel: ChannelStandard, Status: "not_affected"},
	}
	ms, st := Evaluate("1.0", deb, rows)
	if len(ms) != 0 || st.BadVersions != 1 {
		t.Errorf("got %+v, %+v", ms, st)
	}
}

func TestSameMatches(t *testing.T) {
	a := eval(t, "1.0", perCVE("CVE-2024-1", ChannelStandard, "0", sp("2.0"), "low"))
	b := eval(t, "1.0", perCVE("CVE-2024-1", ChannelStandard, "0", sp("2.0"), "low"))
	if !SameMatches(a, b) {
		t.Error("identical sets differ")
	}
	c := eval(t, "1.0", perCVE("CVE-2024-1", ChannelStandard, "0", sp("2.1"), "low"))
	if SameMatches(a, c) || SameMatches(a, nil) || !SameMatches(nil, nil) {
		t.Error("SameMatches wrong")
	}
}

func derefS(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
