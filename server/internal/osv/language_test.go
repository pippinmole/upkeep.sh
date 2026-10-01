package osv

import (
	"encoding/json"
	"strings"
	"testing"
)

// Language fixtures are real records from OSV's top-level npm/all.zip
// (fetched 2026-09-29), unmodified.

func TestNormalizeNpmGHSA(t *testing.T) {
	a, ok := load(t, "npm_ghsa_two_cves.json", "osv-npm")
	if !ok {
		t.Fatal("npm record must be relevant")
	}
	// Two CVE aliases: keyed by its own id; the matcher expands it to
	// each CVE (like a DSA citing several).
	if a.VulnKey != "GHSA-35jh-r3h4-6jhm" || strings.Join(a.CVEIDs, ",") != "CVE-2021-23337,CVE-2026-4800" {
		t.Errorf("vuln_key/cve_ids = %s/%v", a.VulnKey, a.CVEIDs)
	}
	if IsPerCVE(a.ID) {
		t.Error("a GHSA is not a per-CVE record")
	}
	// Its one CVSS is not per CVE: not stored.
	if a.CVSSv3Vector != "" {
		t.Errorf("cvss = %q, want none for a multi-CVE record", a.CVSSv3Vector)
	}
	rows := rowsByKey(t, a)
	// lodash-rails is a RubyGems package: not imported.
	if len(rows) != 4 {
		t.Fatalf("rows = %+v, want the 4 npm packages", a.Affected)
	}
	for name, want := range map[string][2]string{
		"lodash": {"4.17.21", ""}, "lodash-es": {"4.17.21", ""},
		"lodash.template": {"", "4.5.0"}, "lodash-template": {"", "1.0.0"},
	} {
		r, ok := rows["npm/"+name+"/"+ChannelStandard]
		if !ok {
			t.Fatalf("missing %s", name)
		}
		fixed, last := strOrEmpty(r.FixedVersion), strOrEmpty(r.LastAffected)
		status := "unfixed"
		if want[0] != "" {
			status = "fixed"
		}
		if r.Distro != "" || r.Release != "npm" || r.Introduced != "0" || fixed != want[0] || last != want[1] ||
			r.Status != status || str(r.DistroSeverity) != "high" || r.Ecosystem != "npm" {
			t.Errorf("%s row = %+v", name, r)
		}
	}
	if k := rows["npm/lodash/standard"].Key(); k != (Key{"", "npm", "lodash"}) {
		t.Errorf("key = %+v", k)
	}
}

func TestNormalizeNpmVersionsOnly(t *testing.T) {
	a, ok := load(t, "npm_ghsa_versions_only.json", "osv-npm")
	if !ok {
		t.Fatal("must be relevant")
	}
	// No CVE: keyed by the GHSA itself, whose CVSS it owns.
	if a.VulnKey != a.ID || len(a.CVEIDs) != 0 {
		t.Errorf("vuln_key/cve_ids = %s/%v", a.VulnKey, a.CVEIDs)
	}
	if !strings.HasPrefix(a.CVSSv3Vector, "CVSS:3.1/") || a.CVSSIfMissing {
		t.Errorf("cvss = %q (if missing %v), want authoritative", a.CVSSv3Vector, a.CVSSIfMissing)
	}
	// No ranges: one exact row per listed version (the package is listed
	// four times, once per version).
	if len(a.Affected) != 4 {
		t.Fatalf("rows = %+v", a.Affected)
	}
	for _, r := range a.Affected {
		if r.SourcePackage != "@opensearch-project/opensearch" || r.LastAffected == nil ||
			*r.LastAffected != r.Introduced || r.FixedVersion != nil || str(r.DistroSeverity) != "critical" {
			t.Errorf("row = %+v", r)
		}
	}
	// The versions lists are kept in raw: they are what matched.
	var raw struct {
		Affected []struct {
			Versions []string `json:"versions"`
		} `json:"affected"`
	}
	if err := json.Unmarshal(a.Raw, &raw); err != nil || len(raw.Affected) != 4 || len(raw.Affected[0].Versions) != 1 {
		t.Errorf("raw affected = %+v (%v)", raw.Affected, err)
	}
}

func TestNormalizeLanguageOnlyImported(t *testing.T) {
	a, ok := load(t, "npm_pypi_gem_ghsa.json", "osv-npm")
	if !ok {
		t.Fatal("must be relevant")
	}
	// One CVE alias: keyed by it; the GHSA's CVSS only fills a CVE no
	// distro record has scored.
	if a.VulnKey != "CVE-2024-47529" {
		t.Errorf("vuln_key = %s", a.VulnKey)
	}
	if a.CVSSv3Vector != "" && !a.CVSSIfMissing {
		t.Error("a GHSA's CVE score must not override a distro's")
	}
	// Only the imported language ecosystems' packages (npm and PyPI, not
	// RubyGems), whichever feed reads it: the same record sits in both
	// npm's and PyPI's all.zip.
	var got []string
	for _, r := range a.Affected {
		got = append(got, r.Release+"/"+r.SourcePackage)
	}
	if strings.Join(got, ",") != "npm/@openc3/tool-common,pypi/openc3" {
		t.Errorf("rows = %v", got)
	}
	if str(a.Affected[0].DistroSeverity) != "moderate" || str(a.Affected[1].DistroSeverity) != "moderate" {
		t.Errorf("severity = %s", str(a.Affected[0].DistroSeverity))
	}
}

// PyPI fixtures: a GHSA and the PYSEC record for the same CVE and
// package, from PyPI/all.zip (2026-09-29) with their `versions` lists
// removed (the ranges are used).
func TestNormalizePyPIGHSAAndPYSEC(t *testing.T) {
	g, ok := load(t, "pypi_ghsa_jinja2.json", "osv-pypi")
	if !ok {
		t.Fatal("GHSA must be relevant")
	}
	p, ok := load(t, "pypi_pysec_jinja2.json", "osv-pypi")
	if !ok {
		t.Fatal("PYSEC must be relevant")
	}
	// Both key the CVE: the matcher dedupes them into one finding.
	if g.VulnKey != "CVE-2025-27516" || p.VulnKey != "CVE-2025-27516" {
		t.Errorf("vuln_keys = %s / %s", g.VulnKey, p.VulnKey)
	}
	for _, a := range []Advisory{g, p} {
		if len(a.Affected) != 1 {
			t.Fatalf("%s rows = %+v", a.ID, a.Affected)
		}
		r := a.Affected[0]
		if r.Distro != "" || r.Release != "pypi" || r.SourcePackage != "jinja2" || r.Introduced != "0" ||
			str(r.FixedVersion) != "3.1.6" || r.Ecosystem != "PyPI" {
			t.Errorf("%s row = %+v", a.ID, r)
		}
		// CVSS v4 only: nothing for cves (it stores v3).
		if a.CVSSv3Vector != "" {
			t.Errorf("%s cvss = %q", a.ID, a.CVSSv3Vector)
		}
	}
	// Only the GHSA carries a reviewed severity.
	if str(g.Affected[0].DistroSeverity) != "moderate" || p.Affected[0].DistroSeverity != nil {
		t.Errorf("severities = %s / %s", str(g.Affected[0].DistroSeverity), str(p.Affected[0].DistroSeverity))
	}
}

// Go fixtures from Go/all.zip (2026-09-29, `versions` lists removed): a
// stdlib record with two branches, and a GO- record without a CVE plus
// the GHSA it aliases.
func TestNormalizeGo(t *testing.T) {
	s, ok := load(t, "go_stdlib.json", "osv-go")
	if !ok {
		t.Fatal("stdlib record must be relevant")
	}
	if s.VulnKey != "CVE-2025-22873" || len(s.Affected) != 2 {
		t.Fatalf("stdlib: key %s rows %+v", s.VulnKey, s.Affected)
	}
	// Range events keep OSV's spelling (no "v"); goversion canonicalises.
	for i, want := range [][2]string{{"0", "1.23.9"}, {"1.24.0-0", "1.24.3"}} {
		r := s.Affected[i]
		if r.Release != "golang" || r.SourcePackage != "stdlib" || r.Introduced != want[0] ||
			str(r.FixedVersion) != want[1] || r.DistroSeverity != nil {
			t.Errorf("stdlib row %d = %+v", i, r)
		}
	}

	g, _ := load(t, "go_ghsa_alias.json", "osv-go")
	h, _ := load(t, "go_ghsa.json", "osv-go")
	// No CVE: the GO record keys by the GHSA it aliases, so both are one
	// finding.
	if g.VulnKey != "GHSA-hxjg-93wc-h8p8" || h.VulnKey != "GHSA-hxjg-93wc-h8p8" {
		t.Errorf("keys = %s / %s", g.VulnKey, h.VulnKey)
	}
	// Only the GHSA owns a severity and the key's CVSS.
	if g.CVSSv3Vector != "" || h.Affected[0].DistroSeverity == nil || *h.Affected[0].DistroSeverity != "high" {
		t.Errorf("GO cvss %q, GHSA severity %s", g.CVSSv3Vector, str(h.Affected[0].DistroSeverity))
	}
	if h.CVSSv3Vector != "" && h.CVSSIfMissing {
		t.Error("the GHSA's own key: its CVSS is authoritative")
	}
	if r := g.Affected[0]; r.SourcePackage != "github.com/komari-monitor/komari" ||
		str(r.FixedVersion) != "0.0.0-20260609084633-98122fa4d110" {
		t.Errorf("GO row = %+v", r)
	}
}

// A package listed several times from the same version (as GO-2025-3448
// lists github.com/CosmWasm/wasmvm/v2): every distinct range is kept,
// numbered by Seq; an identical one is dropped.
func TestNormalizeLanguageSameIntroduced(t *testing.T) {
	rec, err := Parse([]byte(`{"id":"GO-2025-3448","modified":"2025-02-10T00:00:00Z","aliases":["CVE-2025-24362"],
		"affected":[
		 {"package":{"name":"github.com/CosmWasm/wasmvm/v2","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.6"}]}]},
		 {"package":{"name":"github.com/CosmWasm/wasmvm/v2","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.1.5"}]}]},
		 {"package":{"name":"github.com/CosmWasm/wasmvm/v2","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.1.5"}]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	a, ok, err := Normalize(rec, "osv-go", testReleases)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if len(a.Affected) != 2 || a.Affected[0].Seq != 0 || a.Affected[1].Seq != 1 ||
		str(a.Affected[0].FixedVersion) != "2.0.6" || str(a.Affected[1].FixedVersion) != "2.1.5" {
		t.Errorf("rows = %+v", a.Affected)
	}
}

func TestLanguageNamePyPI(t *testing.T) {
	for in, want := range map[string]string{
		"Django": "django", "zope.interface": "zope-interface",
		"Foo__Bar-.baz": "foo-bar-baz", "jinja2": "jinja2",
	} {
		if got := languageName("PyPI", in); got != want {
			t.Errorf("languageName(%q) = %q, want %q", in, got, want)
		}
	}
	if languageName("npm", "@Scope/Name") != "@Scope/Name" {
		t.Error("npm names are kept")
	}
}

func TestNormalizeMalicious(t *testing.T) {
	rec, err := Parse([]byte(`{"id":"MAL-2024-1","modified":"2024-01-01T00:00:00Z",
		"affected":[{"package":{"name":"evil","ecosystem":"npm"},"versions":["1.0.0"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := Normalize(rec, "osv-npm", testReleases); ok || err != nil {
		t.Errorf("MAL record: relevant=%v err=%v", ok, err)
	}
}

func TestVulnKeyGHSAAlias(t *testing.T) {
	for _, tt := range []struct {
		id      string
		cves    []string
		aliases []string
		want    string
	}{
		{"GO-2024-2687", []string{"CVE-2023-45288"}, []string{"CVE-2023-45288", "GHSA-4v7x-pqxf-cx7m"}, "CVE-2023-45288"},
		{"GO-2024-3333", nil, []string{"GHSA-bbbb-cccc-dddd", "GHSA-aaaa-cccc-dddd"}, "GHSA-aaaa-cccc-dddd"},
		{"GHSA-aaaa-cccc-dddd", nil, []string{"GO-2024-3333"}, "GHSA-aaaa-cccc-dddd"},
		{"PYSEC-2021-19", nil, nil, "PYSEC-2021-19"},
		{"GHSA-aaaa-cccc-dddd", []string{"CVE-2024-1", "CVE-2024-2"}, nil, "GHSA-aaaa-cccc-dddd"},
	} {
		if got := vulnKey(tt.id, tt.cves, tt.aliases); got != tt.want {
			t.Errorf("vulnKey(%s) = %s, want %s", tt.id, got, tt.want)
		}
	}
}

func TestFeedFingerprint(t *testing.T) {
	if FeedFingerprint("npm", testReleases) == FeedFingerprint("Debian", testReleases) {
		t.Error("language fingerprint must differ from a distro's")
	}
	if DistroFor("npm") != "" || DistroFor("Alpine") != "alpine" {
		t.Error("DistroFor")
	}
}

func strOrEmpty(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
