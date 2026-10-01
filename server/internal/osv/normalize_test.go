package osv

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fixtures in testdata/ are real OSV records (fetched 2026-09-26) with
// `versions` / `binaries` arrays and long `details` shortened.

var testReleases = NewReleases([]Release{
	{"debian", "bullseye", "11", false},
	{"debian", "bookworm", "12", true},
	{"debian", "trixie", "13", true},
	{"debian", "forky", "14", false},
	{"ubuntu", "focal", "20.04", false},
	{"ubuntu", "jammy", "22.04", true},
	{"ubuntu", "noble", "24.04", true},
	{"ubuntu", "questing", "25.10", false},
	{"alpine", "3.20", "3.20", false},
	{"alpine", "3.22", "3.22", true},
	{"alpine", "3.24", "3.24", true},
})

func load(t *testing.T, name, source string) (Advisory, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	adv, ok, err := Normalize(rec, source, testReleases)
	if err != nil {
		t.Fatal(err)
	}
	return adv, ok
}

func str(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// rowsByKey indexes rows as "release/package/channel" for assertions.
func rowsByKey(t *testing.T, a Advisory) map[string]AffectedRow {
	t.Helper()
	m := map[string]AffectedRow{}
	for _, r := range a.Affected {
		k := r.Release + "/" + r.SourcePackage + "/" + r.Channel
		if _, dup := m[k]; dup {
			t.Fatalf("duplicate row %s", k)
		}
		m[k] = r
	}
	return m
}

func TestNormalizeDSAWithFix(t *testing.T) {
	a, ok := load(t, "dsa_fixed.json", "osv-debian")
	if !ok {
		t.Fatal("DSA affecting bookworm/trixie must be relevant")
	}
	if a.ID != "DSA-6189-1" || a.Source != "osv-debian" {
		t.Fatalf("id/source = %s/%s", a.ID, a.Source)
	}
	// Two CVEs -> the advisory id is the key; cve_ids lists both.
	if a.VulnKey != "DSA-6189-1" {
		t.Errorf("vuln_key = %s, want DSA-6189-1", a.VulnKey)
	}
	if strings.Join(a.CVEIDs, ",") != "CVE-2026-33416,CVE-2026-33636" {
		t.Errorf("cve_ids = %v", a.CVEIDs)
	}
	if a.CVSSv3Vector != "" {
		t.Errorf("multi-CVE advisory must not carry a per-CVE CVSS vector")
	}
	rows := rowsByKey(t, a)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2: %+v", len(rows), a.Affected)
	}
	b := rows["bookworm/libpng1.6/standard"]
	if b.Distro != "debian" || str(b.FixedVersion) != "1.6.39-2+deb12u4" || b.Status != "fixed" ||
		b.Introduced != "0" || b.Ecosystem != "Debian:12" || b.DistroSeverity != nil {
		t.Errorf("bookworm row = %+v", b)
	}
	if str(rows["trixie/libpng1.6/standard"].FixedVersion) != "1.6.48-1+deb13u4" {
		t.Errorf("trixie row = %+v", rows["trixie/libpng1.6/standard"])
	}
	if a.Modified != time.Date(2026, 3, 31, 22, 31, 29, 677499000, time.UTC) {
		t.Errorf("modified = %v", a.Modified)
	}
}

func TestNormalizeDebianCVEUnfixed(t *testing.T) {
	a, ok := load(t, "debian_cve_unfixed.json", "osv-debian")
	if !ok {
		t.Fatal("not relevant")
	}
	if a.VulnKey != "CVE-2026-48933" || strings.Join(a.CVEIDs, ",") != "CVE-2026-48933" {
		t.Errorf("vuln_key/cve_ids = %s %v", a.VulnKey, a.CVEIDs)
	}
	if a.CVSSv3Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" {
		t.Errorf("cvss = %q", a.CVSSv3Vector)
	}
	rows := rowsByKey(t, a)
	// forky (Debian:14) is unsupported in testReleases and must be dropped.
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", a.Affected)
	}
	bw := rows["bookworm/nodejs/standard"]
	if bw.FixedVersion != nil || bw.Status != "unfixed" || bw.Introduced != "0" {
		t.Errorf("bookworm must be unfixed: %+v", bw)
	}
	// "not yet assigned" urgency normalizes to NULL.
	if bw.DistroSeverity != nil {
		t.Errorf("severity = %s, want nil", str(bw.DistroSeverity))
	}
	tx := rows["trixie/nodejs/standard"]
	if tx.Status != "fixed" || str(tx.FixedVersion) != "20.19.2+dfsg-1+deb13u3" {
		t.Errorf("trixie = %+v", tx)
	}
	// raw keeps only the supported releases' affected entries, without versions.
	var raw struct {
		Affected []map[string]json.RawMessage `json:"affected"`
	}
	if err := json.Unmarshal(a.Raw, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Affected) != 2 {
		t.Errorf("raw affected = %d, want 2", len(raw.Affected))
	}
	for _, e := range raw.Affected {
		if _, has := e["versions"]; has {
			t.Error("raw still has versions")
		}
	}
}

func TestNormalizeUSN(t *testing.T) {
	a, ok := load(t, "usn.json", "osv-ubuntu")
	if !ok {
		t.Fatal("not relevant")
	}
	if a.VulnKey != "USN-8643-4" || len(a.CVEIDs) != 4 {
		t.Errorf("vuln_key/cve_ids = %s %v", a.VulnKey, a.CVEIDs)
	}
	rows := rowsByKey(t, a)
	// The FIPS-updates variant ecosystem is not imported.
	if len(rows) != 4 {
		t.Fatalf("rows = %d: %+v", len(rows), a.Affected)
	}
	r := rows["jammy/linux-aws-6.8/standard"]
	if r.Distro != "ubuntu" || str(r.FixedVersion) != "6.8.0-1063.66~22.04.1" || r.Status != "fixed" {
		t.Errorf("jammy row = %+v", r)
	}
	// USN severity: highest Ubuntu priority across its cves_map (high > medium > low).
	if str(r.DistroSeverity) != "high" {
		t.Errorf("severity = %s, want high", str(r.DistroSeverity))
	}
	if _, ok := rows["noble/linux-nvidia-tegra/standard"]; !ok {
		t.Error("missing noble row")
	}
	var raw struct {
		Affected []struct {
			EcosystemSpecific map[string]json.RawMessage `json:"ecosystem_specific"`
		} `json:"affected"`
	}
	if err := json.Unmarshal(a.Raw, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Affected) != 4 {
		t.Errorf("raw affected = %d, want 4", len(raw.Affected))
	}
	for _, e := range raw.Affected {
		if _, has := e.EcosystemSpecific["binaries"]; has {
			t.Error("raw still has binaries")
		}
		if _, has := e.EcosystemSpecific["availability"]; !has {
			t.Error("raw lost availability")
		}
	}
}

func TestNormalizeUbuntuESM(t *testing.T) {
	a, ok := load(t, "ubuntu_cve_esm.json", "osv-ubuntu")
	if !ok {
		t.Fatal("not relevant")
	}
	if a.VulnKey != "CVE-2025-10256" || str(a.Severity) != "medium" {
		t.Errorf("vuln_key/severity = %s %s", a.VulnKey, str(a.Severity))
	}
	if a.CVSSv3Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" {
		t.Errorf("cvss = %q (want the first CVSS_V3)", a.CVSSv3Vector)
	}
	rows := rowsByKey(t, a)
	// Pro 18.04/20.04 and 25.10 are unsupported; Pro 22.04 and Pro 24.04 map
	// onto jammy/noble in the ubuntu-pro channel.
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", a.Affected)
	}
	j := rows["jammy/ffmpeg/ubuntu-pro"]
	if j.Channel != ChannelUbuntuPro || j.Ecosystem != "Ubuntu:Pro:22.04:LTS" ||
		str(j.FixedVersion) != "7:4.4.2-0ubuntu0.22.04.1+esm10" || j.Status != "fixed" {
		t.Errorf("jammy ESM row = %+v", j)
	}
	// Record-level Ubuntu priority applies when the package has no override.
	if str(j.DistroSeverity) != "medium" {
		t.Errorf("severity = %s", str(j.DistroSeverity))
	}
	if _, ok := rows["noble/ffmpeg/ubuntu-pro"]; !ok {
		t.Error("missing noble ESM row")
	}
}

func TestNormalizeUnsupportedReleaseSkipped(t *testing.T) {
	a, ok := load(t, "dla_unsupported_release.json", "osv-debian")
	if ok || len(a.Affected) != 0 {
		t.Fatalf("DLA for bullseye only must be irrelevant, got ok=%v rows=%v", ok, a.Affected)
	}
}

func TestNormalizeWithdrawn(t *testing.T) {
	a, ok := load(t, "debian_cve_withdrawn.json", "osv-debian")
	if !ok {
		t.Fatal("withdrawn record in a supported release is still stored")
	}
	if a.Withdrawn == nil || len(a.Affected) != 0 {
		t.Errorf("withdrawn = %v, rows = %v; want set, none", a.Withdrawn, a.Affected)
	}
}

func TestContentHashStable(t *testing.T) {
	a1, _ := load(t, "usn.json", "osv-ubuntu")
	a2, _ := load(t, "usn.json", "osv-ubuntu")
	if a1.ContentHash == "" || a1.ContentHash != a2.ContentHash {
		t.Fatalf("hash not stable: %s vs %s", a1.ContentHash, a2.ContentHash)
	}
	// Enabling a release changes the normalized rows and so the hash.
	b, _ := os.ReadFile(filepath.Join("testdata", "ubuntu_cve_esm.json"))
	rec, _ := Parse(b)
	x, _, _ := Normalize(rec, "osv-ubuntu", testReleases)
	y, _, _ := Normalize(rec, "osv-ubuntu", NewReleases([]Release{{"ubuntu", "jammy", "22.04", true}}))
	if x.ContentHash == y.ContentHash {
		t.Error("hash ignores the supported release set")
	}
}

func TestParseEcosystem(t *testing.T) {
	cases := []struct {
		in, distro, version, channel string
		ok                           bool
	}{
		{"Debian:12", "debian", "12", ChannelStandard, true},
		{"Debian:3.0", "debian", "3.0", ChannelStandard, true},
		{"Ubuntu:22.04:LTS", "ubuntu", "22.04", ChannelStandard, true},
		{"Ubuntu:25.10", "ubuntu", "25.10", ChannelStandard, true},
		{"Ubuntu:26.04", "ubuntu", "26.04", ChannelStandard, true},
		{"Ubuntu:Pro:22.04:LTS", "ubuntu", "22.04", ChannelUbuntuPro, true},
		{"Ubuntu:Pro:FIPS-updates:22.04:LTS", "", "", "", false},
		{"Ubuntu:Pro:Realtime:24.04:LTS", "", "", "", false},
		{"Ubuntu:Pro:22.04:LTS:Realtime:Kernel", "", "", "", false},
		{"Ubuntu:Nvidia-BlueField:22.04:LTS", "", "", "", false},
		{"Ubuntu:22.04:LTS:for:NVIDIA:BlueField", "", "", "", false},
		{"Debian", "", "", "", false},
		{"Alpine:v3.20", "alpine", "3.20", ChannelStandard, true},
		{"Alpine:v3.9", "alpine", "3.9", ChannelStandard, true},
		{"Alpine:3.20", "", "", "", false},
		{"Alpine:vedge", "", "", "", false},
		{"Alpine", "", "", "", false},
	}
	for _, c := range cases {
		d, v, ch, ok := ParseEcosystem(c.in)
		if ok != c.ok || d != c.distro || v != c.version || ch != c.channel {
			t.Errorf("%s = %q %q %q %v", c.in, d, v, ch, ok)
		}
	}
}

func TestRangeRows(t *testing.T) {
	s := func(v string) *string { return &v }
	rows := rangeRows([]Event{
		{Introduced: s("0")},
		{Fixed: s("1.0-1")},
		{Introduced: s("2.0-1")},
		{LastAffected: s("2.0-3")},
		{Introduced: s("3.0-1")},
	})
	if len(rows) != 3 ||
		str(rows[0].FixedVersion) != "1.0-1" ||
		rows[1].Introduced != "2.0-1" || str(rows[1].LastAffected) != "2.0-3" || rows[1].FixedVersion != nil ||
		rows[2].Introduced != "3.0-1" || rows[2].FixedVersion != nil {
		t.Errorf("rows = %+v", rows)
	}
}

func TestParseModifiedCSV(t *testing.T) {
	in := "2026-09-26T17:00:08.452254675Z,DEBIAN-CVE-2026-48933\n" +
		"2026-09-26T16:00:00Z,DSA-1-1\n" +
		"2026-09-26T15:00:00Z,DSA-2-1\n" +
		"2026-09-26T14:00:00Z,DSA-3-1\n"
	got, err := ParseModifiedCSV(strings.NewReader(in), time.Date(2026, 9, 26, 15, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "DEBIAN-CVE-2026-48933" || got[1].ID != "DSA-1-1" {
		t.Errorf("got %+v", got)
	}
}
