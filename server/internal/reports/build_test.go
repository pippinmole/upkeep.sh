package reports

import (
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/findings"
	"github.com/pippinmole/upkeep.sh/server/internal/severity"
)

var (
	t0    = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	now   = time.Date(2026, 9, 28, 7, 0, 0, 0, time.UTC)
	sched = ScheduleRef{ID: "sched-1", Name: "Weekly", Cadence: CadenceWeekly, Timezone: "Europe/London"}
	per   = Period{Start: now.AddDate(0, 0, -7), End: now}
)

func sp(s string) *string      { return &s }
func fp(f float64) *float64    { return &f }
func day(n int) time.Time      { return t0.AddDate(0, 0, n) }
func build(in Inputs) Snapshot { return Build(in, sched, TriggerScheduled, per, now) }

// pkgF is an open vulnerable_package finding on host, jammy deb.
func pkgF(host, source, vuln string, fixed *string, sev severity.Bucket, mods ...func(*InputFinding)) InputFinding {
	f := InputFinding{
		HostID: host, Kind: findings.KindVulnerablePackage, VulnKey: vuln, SourcePackage: source,
		Ecosystem: "deb", Distro: "ubuntu", Release: "jammy", Packages: []string{source},
		FixedVersion: fixed, Severity: sev, FirstSeenAt: t0,
	}
	if fixed != nil {
		f.FixChannel = "standard"
	}
	for _, m := range mods {
		m(&f)
	}
	return f
}

// imgF is an open vulnerable_image finding for image k on host.
func imgF(host string, k ImageKey, source, vuln string, fixChannel string, sev severity.Bucket, mods ...func(*InputFinding)) InputFinding {
	f := InputFinding{HostID: host, Kind: findings.KindVulnerableImage, VulnKey: vuln, SourcePackage: source,
		Packages: []string{source}, Severity: sev, FirstSeenAt: t0, Image: &k, FixChannel: fixChannel}
	if fixChannel != "" {
		f.FixedVersion = sp("9.9")
	}
	for _, m := range mods {
		m(&f)
	}
	return f
}

func kev(f *InputFinding)                  { f.KEV = true }
func epss(e float64) func(*InputFinding)   { return func(f *InputFinding) { f.EPSS = fp(e) } }
func seen(t time.Time) func(*InputFinding) { return func(f *InputFinding) { f.FirstSeenAt = t } }
func bins(p ...string) func(*InputFinding) { return func(f *InputFinding) { f.Packages = p } }
func release(r string) func(*InputFinding) { return func(f *InputFinding) { f.Release = r } }
func channel(c string) func(*InputFinding) { return func(f *InputFinding) { f.FixChannel = c } }

var threeHosts = []InputHost{{ID: "h1", Name: "web-1"}, {ID: "h2", Name: "db-1"}, {ID: "h3", Name: "web-2"}}

func TestHostActionGroupingAndHighestFix(t *testing.T) {
	in := Inputs{
		Hosts: threeHosts,
		Findings: []InputFinding{
			// openssl on jammy: CVEs need 1.2-1 and 1.10-1; dpkg order makes
			// 1.10 the highest (byte order would pick 1.2).
			pkgF("h1", "openssl", "CVE-2026-0002", sp("1.2-1"), severity.BucketMedium, bins("libssl3"), epss(0.02), seen(day(3))),
			pkgF("h1", "openssl", "CVE-2026-0001", sp("1.10-1"), severity.BucketHigh, bins("libssl3", "openssl"), epss(0.05)),
			pkgF("h2", "openssl", "CVE-2026-0001", sp("1.10-1"), severity.BucketHigh, bins("openssl"), seen(day(-2))),
			// Same package on noble: its own line, its own version.
			pkgF("h3", "openssl", "CVE-2026-0001", sp("1.10-1ubuntu24"), severity.BucketHigh, release("noble")),
			// Pro-only fix: its own line, never merged into the standard one.
			pkgF("h1", "openssl", "CVE-2026-0003", sp("1.10-1+esm1"), severity.BucketLow, channel("ubuntu-pro")),
		},
	}
	s := build(in)
	if len(s.HostActions) != 3 {
		t.Fatalf("host actions = %+v", s.HostActions)
	}
	a := s.HostActions[0]
	if a.Package != "openssl" || a.FixedVersion != "1.10-1" || a.FixChannel != "standard" || a.RequiresPro {
		t.Errorf("first action = %+v", a)
	}
	if !slices.Equal(a.CVEs, []string{"CVE-2026-0001", "CVE-2026-0002"}) || a.CVECount != 2 {
		t.Errorf("cves = %v (%d)", a.CVEs, a.CVECount)
	}
	if !slices.Equal(a.BinaryPackages, []string{"libssl3", "openssl"}) {
		t.Errorf("binary packages = %v", a.BinaryPackages)
	}
	if !reflect.DeepEqual(a.Hosts, []HostRef{{"h2", "db-1"}, {"h1", "web-1"}}) || a.HostCount != 2 {
		t.Errorf("hosts = %v (%d)", a.Hosts, a.HostCount)
	}
	if !a.OldestOpenAt.Equal(day(-2)) || a.WorstSeverity != "high" || a.MaxEPSS == nil || *a.MaxEPSS != 0.05 || a.KEV {
		t.Errorf("stats = oldest %v worst %s epss %v kev %v", a.OldestOpenAt, a.WorstSeverity, a.MaxEPSS, a.KEV)
	}
	if a.Tier != TierPatchThisWeek {
		t.Errorf("tier = %s", a.Tier)
	}
	noble := s.HostActions[1]
	if noble.FixedVersion != "1.10-1ubuntu24" || noble.HostCount != 1 || noble.MaxEPSS != nil {
		t.Errorf("noble action = %+v", noble)
	}
	pro := s.HostActions[2]
	if !pro.RequiresPro || pro.FixChannel != "ubuntu-pro" || pro.Tier != TierWhenConvenient || pro.FixedVersion != "1.10-1+esm1" {
		t.Errorf("pro action = %+v", pro)
	}
	if s.NoFix.Findings != 0 || s.Headline.TotalOpenFindings != 5 {
		t.Errorf("no fix %+v, total %d", s.NoFix, s.Headline.TotalOpenFindings)
	}
	assertNoNilLists(t, s)
}

func TestVersionLess(t *testing.T) {
	for _, c := range []struct {
		eco, a, b string
		want      bool
	}{
		{"deb", "1.2-1", "1.10-1", true},
		{"deb", "2:1.0", "1.9", false},  // epoch
		{"deb", "1.0~rc1", "1.0", true}, // tilde sorts first
		{"apk", "1.2.3-r9", "1.2.3-r10", true},
		{"deb", "not a version!", "1.0", true}, // valid beats invalid
		{"deb", "1.0", "not a version!", false},
		{"unknown", "b", "a", false}, // byte order fallback
	} {
		if got := versionLess(c.eco, c.a, c.b); got != c.want {
			t.Errorf("versionLess(%s, %q, %q) = %v, want %v", c.eco, c.a, c.b, got, c.want)
		}
	}
}

func TestTiers(t *testing.T) {
	fix := sp("2.0-1")
	in := Inputs{
		Hosts: threeHosts,
		Findings: []InputFinding{
			pkgF("h1", "kevpkg", "CVE-1", fix, severity.BucketLow, kev),                // KEV: patch now
			pkgF("h1", "critpkg", "CVE-2", fix, severity.BucketCritical),               // critical with a fix
			pkgF("h1", "epsspkg", "CVE-3", fix, severity.BucketNegligible, epss(0.10)), // EPSS at the threshold
			pkgF("h1", "lowepss", "CVE-4", fix, severity.BucketMedium, epss(0.0999)),   // just below
			pkgF("h1", "unknown", "CVE-5", fix, severity.BucketUnknown),
			// A line's tier is its most urgent finding's.
			pkgF("h2", "mixed", "CVE-6", fix, severity.BucketLow),
			pkgF("h2", "mixed", "CVE-7", fix, severity.BucketHigh),
		},
	}
	s := build(in)
	got := map[string]string{}
	for _, a := range s.HostActions {
		got[a.Package] = a.Tier
	}
	want := map[string]string{
		"kevpkg": TierPatchNow, "critpkg": TierPatchThisWeek, "epsspkg": TierPatchThisWeek,
		"lowepss": TierWhenConvenient, "unknown": TierWhenConvenient, "mixed": TierPatchThisWeek,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tiers = %v, want %v", got, want)
	}
	h := s.Headline
	if h.PatchNow != 1 || h.PatchThisWeek != 3 || h.WhenConvenient != 2 {
		t.Errorf("headline = %+v", h)
	}
	if kevLine := s.HostActions[0]; kevLine.Package != "kevpkg" || !kevLine.KEV || kevLine.WorstSeverity != "low" {
		t.Errorf("first action = %+v", kevLine)
	}
}

func TestNoFix(t *testing.T) {
	k := ImageKey{ImageID: "sha256:a", OS: "linux", Arch: "amd64"}
	in := Inputs{
		Hosts: threeHosts,
		Findings: []InputFinding{
			pkgF("h1", "openssl", "CVE-1", nil, severity.BucketCritical, kev), // KEV without a fix
			pkgF("h1", "zlib", "CVE-2", nil, severity.BucketMedium),
			imgF("h2", k, "curl", "CVE-3", "", severity.BucketHigh),
			imgF("h2", k, "curl", "CVE-4", "ubuntu-pro", severity.BucketLow), // no fix a re-pull picks up
		},
		Containers: []InputContainer{{HostID: "h2", Name: "app", Image: &k}},
		Images:     []InputImage{{Key: k, Refs: []string{"app:1"}}},
	}
	s := build(in)
	if len(s.HostActions) != 0 || len(s.ImageActions) != 0 {
		t.Fatalf("actions: %+v %+v", s.HostActions, s.ImageActions)
	}
	want := NoFix{Findings: 4, KEVFindings: 1, WorstSeverity: sp("critical"), HostPackageFindings: 2, ImageFindings: 2}
	if !reflect.DeepEqual(s.NoFix, want) {
		t.Errorf("no fix = %+v, want %+v", s.NoFix, want)
	}
	if s.Headline.NoFixFindings != 4 || s.Headline.PatchNow != 0 || s.Headline.ImagesToUpdate != 0 {
		t.Errorf("headline = %+v", s.Headline)
	}
	if hs := hostByID(s, "h1"); hs.NoFixFindings != 2 || hs.TotalOpenFindings != 2 || hs.PatchNow != 0 {
		t.Errorf("h1 = %+v", hs)
	}
}

func TestImageActions(t *testing.T) {
	nginx := ImageKey{ImageID: "sha256:nginx", OS: "linux", Arch: "arm64", Variant: "v8"}
	redis := ImageKey{ImageID: "sha256:redis", OS: "linux", Arch: "amd64"}
	unscored := ImageKey{ImageID: "sha256:private", OS: "linux", Arch: "amd64"}
	in := Inputs{
		Hosts: threeHosts,
		Findings: []InputFinding{
			imgF("h1", nginx, "openssl", "CVE-1", "standard", severity.BucketHigh, epss(0.3), seen(day(2))),
			imgF("h1", nginx, "zlib", "CVE-2", "standard", severity.BucketMedium, seen(day(1))),
			imgF("h1", nginx, "curl", "CVE-3", "", severity.BucketCritical, kev, seen(day(-5))), // unfixed: no_fix only
			imgF("h3", nginx, "openssl", "CVE-1", "standard", severity.BucketHigh, seen(day(4))),
			imgF("h2", redis, "glibc", "CVE-4", "", severity.BucketHigh), // nothing fixable
		},
		Containers: []InputContainer{
			{HostID: "h1", Name: "proxy", Image: &nginx},
			{HostID: "h3", Name: "static-site", Image: &nginx},
			{HostID: "h3", Name: "proxy", Image: &nginx},
			{HostID: "h2", Name: "cache", Image: &redis},
			{HostID: "h2", Name: "api", Image: &unscored},
			{HostID: "h2", Name: "uninspected"},
		},
		Images: []InputImage{
			{Key: nginx, Refs: []string{"nginx:1.27", "nginx:latest"}},
			{Key: redis, Refs: []string{"redis:7"}},
			{Key: unscored, Refs: []string{"ghcr.io/me/api:1"}, NotScored: "unavailable"},
		},
	}
	s := build(in)
	if len(s.ImageActions) != 1 {
		t.Fatalf("image actions = %+v", s.ImageActions)
	}
	a := s.ImageActions[0]
	want := ImageAction{
		Tier: TierPatchThisWeek, ImageID: "sha256:nginx", ImageRefs: []string{"nginx:1.27", "nginx:latest"},
		OS: "linux", Arch: "arm64", Variant: "v8", KEV: false, WorstSeverity: "high", MaxEPSS: fp(0.3),
		OpenFindings: 4, FixableFindings: 3, Containers: []string{"proxy", "static-site"},
		Hosts: []HostRef{{"h1", "web-1"}, {"h3", "web-2"}}, OldestOpenAt: day(1),
	}
	if !reflect.DeepEqual(a, want) {
		t.Errorf("image action =\n%+v\nwant\n%+v", a, want)
	}
	if s.NoFix.ImageFindings != 2 || s.NoFix.KEVFindings != 1 {
		t.Errorf("no fix = %+v", s.NoFix)
	}
	if s.Estate != (Estate{Hosts: 3, Containers: 6, Images: 3}) {
		t.Errorf("estate = %+v", s.Estate)
	}
	if !reflect.DeepEqual(s.Coverage.ImagesNotScored, []ImageNotScored{{ImageID: "sha256:private",
		ImageRefs: []string{"ghcr.io/me/api:1"}, OS: "linux", Arch: "amd64", Status: "unavailable"}}) {
		t.Errorf("not scored = %+v", s.Coverage.ImagesNotScored)
	}
	if s.Headline.ImagesToUpdate != 1 || s.Headline.PatchThisWeek != 1 {
		t.Errorf("headline = %+v", s.Headline)
	}
	if h := hostByID(s, "h3"); h.ImagesToUpdate != 1 || h.PatchThisWeek != 1 || h.TotalOpenFindings != 1 {
		t.Errorf("h3 = %+v", h)
	}
	if h := hostByID(s, "h2"); h.ImagesToUpdate != 0 || h.NoFixFindings != 1 {
		t.Errorf("h2 = %+v", h)
	}
}

func TestCoverageRebootsAndHosts(t *testing.T) {
	seenAt, since := day(10), day(20)
	in := Inputs{
		Hosts: threeHosts,
		Findings: []InputFinding{
			pkgF("h1", "openssl", "CVE-1", sp("2"), severity.BucketHigh, kev),
			pkgF("h3", "openssl", "CVE-1", sp("2"), severity.BucketHigh, kev),
		},
		Reboots: []InputReboot{
			{HostID: "h3", Packages: []string{"linux-image-6.8", "libc6", "libc6"}, Since: &since},
			{HostID: "h1", Packages: nil},
		},
		StaleAgents: []InputAgent{
			{ID: "a2", Name: "zeta", LastSeenAt: &seenAt, HostIDs: []string{"h3", "h1"}},
			{ID: "a1", Name: "alpha", LastSeenAt: &seenAt, HostIDs: []string{"h2"}},
		},
		HostsWithoutDocker: []string{"h3", "h2"},
		Opened:             7, Resolved: 2,
	}
	s := build(in)
	if len(s.RebootsRequired) != 2 || s.RebootsRequired[0].HostName != "web-1" ||
		!slices.Equal(s.RebootsRequired[1].Packages, []string{"libc6", "linux-image-6.8"}) ||
		s.RebootsRequired[0].Packages == nil || s.RebootsRequired[0].Since != nil {
		t.Errorf("reboots = %+v", s.RebootsRequired)
	}
	c := s.Coverage
	if len(c.StaleAgents) != 2 || c.StaleAgents[0].Name != "alpha" ||
		!reflect.DeepEqual(c.StaleAgents[1].Hosts, []HostRef{{"h1", "web-1"}, {"h3", "web-2"}}) {
		t.Errorf("stale agents = %+v", c.StaleAgents)
	}
	if !reflect.DeepEqual(c.HostsWithoutDocker, []HostRef{{"h2", "db-1"}, {"h3", "web-2"}}) {
		t.Errorf("hosts without docker = %+v", c.HostsWithoutDocker)
	}
	want := Headline{PatchNow: 1, RebootsRequired: 2, TotalOpenFindings: 2, OpenedSinceLast: 7, ResolvedSinceLast: 2, StaleAgents: 2}
	if s.Headline != want {
		t.Errorf("headline = %+v, want %+v", s.Headline, want)
	}
	wantHosts := []HostSummary{
		{ID: "h2", Name: "db-1"},
		{ID: "h1", Name: "web-1", PatchNow: 1, RebootRequired: true, TotalOpenFindings: 1},
		{ID: "h3", Name: "web-2", PatchNow: 1, RebootRequired: true, TotalOpenFindings: 1},
	}
	if !reflect.DeepEqual(s.Hosts, wantHosts) {
		t.Errorf("hosts = %+v", s.Hosts)
	}
	if s.SchemaVersion != SchemaVersion || s.RankingVersion != RankingVersion || s.Trigger != TriggerScheduled ||
		!s.GeneratedAt.Equal(now) || s.Period != per || s.Schedule != sched || s.Changes != nil {
		t.Errorf("header = %+v", s)
	}
	assertNoNilLists(t, s)
}

// The same inputs in any order give the same snapshot, actions sorted by
// tier, then KEV, then severity, then host count, then package.
func TestDeterministicOrdering(t *testing.T) {
	fix := sp("2.0-1")
	k := ImageKey{ImageID: "sha256:a", OS: "linux", Arch: "amd64"}
	in := Inputs{
		Hosts: threeHosts,
		Findings: []InputFinding{
			pkgF("h1", "b-kev-low", "CVE-1", fix, severity.BucketLow, kev),
			pkgF("h1", "a-kev-crit", "CVE-2", fix, severity.BucketCritical, kev),
			pkgF("h1", "c-high-1host", "CVE-3", fix, severity.BucketHigh),
			pkgF("h1", "d-high-2hosts", "CVE-4", fix, severity.BucketHigh),
			pkgF("h2", "d-high-2hosts", "CVE-4", fix, severity.BucketHigh),
			pkgF("h1", "e-crit", "CVE-5", fix, severity.BucketCritical),
			pkgF("h1", "f-high-1host", "CVE-6", fix, severity.BucketHigh),
			pkgF("h1", "g-medium", "CVE-7", fix, severity.BucketMedium),
			pkgF("h2", "h-none", "CVE-8", nil, severity.BucketMedium),
			imgF("h1", k, "x", "CVE-9", "standard", severity.BucketMedium),
		},
		Containers: []InputContainer{{HostID: "h1", Name: "b", Image: &k}, {HostID: "h1", Name: "a", Image: &k}},
		Images:     []InputImage{{Key: k, Refs: []string{"a:1"}}},
	}
	want := build(in)
	var order []string
	for _, a := range want.HostActions {
		order = append(order, a.Package)
	}
	wantOrder := []string{"a-kev-crit", "b-kev-low", "e-crit", "d-high-2hosts", "c-high-1host", "f-high-1host", "g-medium"}
	if !slices.Equal(order, wantOrder) {
		t.Errorf("order = %v, want %v", order, wantOrder)
	}
	r := rand.New(rand.NewPCG(1, 2))
	for range 20 {
		shuffled := in
		shuffled.Hosts = slices.Clone(in.Hosts)
		shuffled.Findings = slices.Clone(in.Findings)
		shuffled.Containers = slices.Clone(in.Containers)
		r.Shuffle(len(shuffled.Hosts), func(i, j int) { shuffled.Hosts[i], shuffled.Hosts[j] = shuffled.Hosts[j], shuffled.Hosts[i] })
		r.Shuffle(len(shuffled.Findings), func(i, j int) {
			shuffled.Findings[i], shuffled.Findings[j] = shuffled.Findings[j], shuffled.Findings[i]
		})
		r.Shuffle(len(shuffled.Containers), func(i, j int) {
			shuffled.Containers[i], shuffled.Containers[j] = shuffled.Containers[j], shuffled.Containers[i]
		})
		if got := build(shuffled); !reflect.DeepEqual(got, want) {
			t.Fatalf("shuffled input gives another snapshot:\n%+v\nwant\n%+v", got, want)
		}
	}
}

func TestEmptyEstate(t *testing.T) {
	s := build(Inputs{})
	assertNoNilLists(t, s)
	if s.Headline != (Headline{}) || s.Estate != (Estate{}) || s.NoFix.WorstSeverity != nil {
		t.Errorf("empty estate = %+v", s)
	}
	c := Compare(&s, "prev", s)
	assertNoNilLists(t, c)
	if len(c.Metrics) != 10 {
		t.Errorf("metrics = %v", c.Metrics)
	}
}

func hostByID(s Snapshot, id string) HostSummary {
	for _, h := range s.Hosts {
		if h.ID == id {
			return h
		}
	}
	return HostSummary{}
}
