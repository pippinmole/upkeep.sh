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
	// Only the imported language ecosystems' packages (npm; RubyGems and,
	// until it is added, PyPI are not).
	var got []string
	for _, r := range a.Affected {
		got = append(got, r.Release+"/"+r.SourcePackage)
	}
	if strings.Join(got, ",") != "npm/@openc3/tool-common" {
		t.Errorf("rows = %v", got)
	}
	if str(a.Affected[0].DistroSeverity) != "moderate" {
		t.Errorf("severity = %s", str(a.Affected[0].DistroSeverity))
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
