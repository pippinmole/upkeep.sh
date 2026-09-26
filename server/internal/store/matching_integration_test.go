package store

// Matcher + findings integration tests against a real, fully migrated
// Postgres; skipped unless SW_TEST_DATABASE_URL is set (see
// inventory_integration_test.go). Everything is scoped to the fixture's
// unique distro tag (advisories, advisory_changes, software_versions) and
// its own user/host, and deleted afterwards.
//
// Safe to run while a dev worker is up: the worker's drain ignores
// distros not in distro_releases, and its sweep evaluating these versions
// concurrently is idempotent (the one timing-sensitive assertion allows
// for it).

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/findings"
	"github.com/pippinmole/upkeep.sh/server/internal/inventory"
	"github.com/pippinmole/upkeep.sh/server/internal/matcher"
	"github.com/pippinmole/upkeep.sh/server/internal/osv"
)

type matchFixture struct {
	*fixture
	cves   []string
	hashes int
}

func newMatchFixture(t *testing.T) *matchFixture {
	f := &matchFixture{fixture: newFixture(t)}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = f.s.Pool.Exec(ctx, `DELETE FROM advisories WHERE source = $1`, f.distro)
		_, _ = f.s.Pool.Exec(ctx, `DELETE FROM advisory_changes WHERE distro = $1`, f.distro)
		_, _ = f.s.Pool.Exec(ctx, `DELETE FROM cves WHERE id = ANY($1)`, f.cves)
	})
	return f
}

// cve returns a CVE id unique to this run.
func (f *matchFixture) cve() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	id := fmt.Sprintf("CVE-1901-%d", 1000000+int(b[0])<<16|int(b[1])<<8|int(b[2]))
	f.cves = append(f.cves, id)
	return id
}

// row is an advisory_affected row in the fixture's distro, release jammy.
func row(source, channel string, fixed *string, sev string) osv.AffectedRow {
	r := osv.AffectedRow{Release: "jammy", SourcePackage: source, Channel: channel, Introduced: "0",
		FixedVersion: fixed, Status: "unfixed", Ecosystem: "Test:22.04"}
	if fixed != nil {
		r.Status = "fixed"
	}
	if sev != "" {
		r.DistroSeverity = sp(sev)
	}
	return r
}

// perCVE builds an UBUNTU-CVE-style per-CVE advisory.
func (f *matchFixture) perCVE(cve string, rows ...osv.AffectedRow) osv.Advisory {
	return f.advisory("UBUNTU-"+cve, cve, []string{cve}, rows...)
}

func (f *matchFixture) advisory(id, vulnKey string, cves []string, rows ...osv.AffectedRow) osv.Advisory {
	f.hashes++
	for i := range rows {
		rows[i].Distro = f.distro
	}
	return osv.Advisory{
		ID: id, Source: f.distro, VulnKey: vulnKey, CVEIDs: cves,
		Aliases: []string{}, Upstream: cves, Related: []string{},
		Modified: f.t0, Raw: []byte(`{}`), ContentHash: fmt.Sprintf("%s-h%d", f.distro, f.hashes), Affected: rows,
	}
}

func (f *matchFixture) upsert(advs ...osv.Advisory) {
	f.t.Helper()
	if _, err := f.s.UpsertAdvisories(context.Background(), advs); err != nil {
		f.t.Fatal(err)
	}
}

// pushK pushes a snapshot with a running kernel (minutes after t0).
func (f *matchFixture) pushK(minute int, kernel string, items ...inventory.Item) SnapshotResult {
	f.t.Helper()
	at := f.t0.Add(time.Duration(minute) * time.Minute)
	res, err := f.s.InsertSnapshot(context.Background(), SnapshotInput{
		HostID: f.hostID, SchemaVersion: 1, CollectedAt: at, InventoryAt: at,
		OSID: f.distro, OSVersionID: "22.04", OSCodename: "jammy", KernelRelease: kernel,
		Inventory: []inventory.Set{f.set(items...)},
	})
	if err != nil {
		f.t.Fatalf("push at +%dm: %v", minute, err)
	}
	return res
}

// matchPush evaluates what a push interned (the match_versions job).
func (f *matchFixture) matchPush(res SnapshotResult) MatchResult {
	f.t.Helper()
	m, err := f.s.MatchVersions(context.Background(), res.RematchSoftwareIDs())
	if err != nil {
		f.t.Fatal(err)
	}
	return m
}

func (f *matchFixture) reconcile() ReconcileResult {
	f.t.Helper()
	r, err := f.s.ReconcileHostFindings(context.Background(), f.hostID)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

type findingRow struct {
	Key, Status, Installed, Fixed, FixChannel, Severity string
	RequiresPro, RunningUnknown                         bool
	Kernel                                              string
	Packages                                            []string
	ReopenCount                                         int
}

func (f *matchFixture) findings() map[string]findingRow {
	f.t.Helper()
	rows, err := f.s.Pool.Query(context.Background(), `
		SELECT dedup_key, status, installed_version, COALESCE(fixed_version, ''), COALESCE(fix_channel, ''),
		       severity, requires_pro, running_kernel_unknown, COALESCE(kernel_release, ''), packages, reopen_count
		FROM findings WHERE host_id = $1 AND kind = 'vulnerable_package'
	`, f.hostID)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]findingRow{}
	for rows.Next() {
		var r findingRow
		if err := rows.Scan(&r.Key, &r.Status, &r.Installed, &r.Fixed, &r.FixChannel, &r.Severity,
			&r.RequiresPro, &r.RunningUnknown, &r.Kernel, &r.Packages, &r.ReopenCount); err != nil {
			f.t.Fatal(err)
		}
		out[r.Key] = r
	}
	return out
}

func (f *matchFixture) statuses() map[string]string {
	out := map[string]string{}
	for k, r := range f.findings() {
		out[k] = r.Status
	}
	return out
}

func srcPkg(name, version, source, sourceVersion string) inventory.Item {
	return inventory.Item{Name: name, Version: version, Arch: "amd64", Source: source, SourceVersion: sourceVersion}
}

func TestMatcherAndFindingsLifecycle(t *testing.T) {
	f := newMatchFixture(t)
	ctx := context.Background()
	cveA, cveB, cveP, cveK, cveK88, cveC := f.cve(), f.cve(), f.cve(), f.cve(), f.cve(), f.cve()

	f.upsert(
		// Per-CVE record: swlib fixed in 1.0-2.
		f.perCVE(cveA, row("swlib", osv.ChannelStandard, sp("1.0-2"), "medium")),
		// A notice citing A and B (no per-CVE record for B): B comes from it.
		f.advisory("USN-"+f.distro, "USN-"+f.distro, []string{cveA, cveB},
			row("swlib", osv.ChannelStandard, sp("1.0-2"), "high")),
		// Pro-only fix: standard unfixed, ESM fixed.
		f.perCVE(cveP, row("swlib", osv.ChannelStandard, nil, "low"),
			row("swlib", osv.ChannelUbuntuPro, sp("1.0-3ubuntu0.1~esm1"), "low")),
		// Kernel CVE fixed in 5.15.0-92, and one only below 5.15.0-89.
		f.perCVE(cveK, row("linux", osv.ChannelStandard, sp("5.15.0-92.102"), "high")),
		f.perCVE(cveK88, row("linux", osv.ChannelStandard, sp("5.15.0-89.99"), "high")),
	)

	const k91, k88 = "5.15.0-91-generic", "5.15.0-88-generic"
	swlib := []inventory.Item{srcPkg("libsw1", "1.0-1", "swlib", "1.0-1"), srcPkg("swlib-bin", "1.0-1", "swlib", "1.0-1")}
	kernels := []inventory.Item{
		srcPkg("linux-image-"+k91, "5.15.0-91.101", "linux-signed", "5.15.0-91.101"),
		srcPkg("linux-modules-"+k91, "5.15.0-91.101", "linux", "5.15.0-91.101"),
		srcPkg("linux-image-"+k88, "5.15.0-88.98", "linux-signed", "5.15.0-88.98"),
		srcPkg("linux-image-generic", "5.15.0.91.88", "linux-meta", "5.15.0.91.88"),
		srcPkg("linux-libc-dev", "5.15.0-91.101", "linux", "5.15.0-91.101"),
	}

	res := f.pushK(1, k91, append(slices.Clone(swlib), kernels...)...)
	if !res.KernelChanged || !res.InventoryChanged() || len(res.RematchSoftwareIDs()) != 7 {
		t.Fatalf("first push: %+v", res)
	}

	// Reconcile before the match job ran: refused (would flap otherwise).
	if _, err := f.s.ReconcileHostFindings(ctx, f.hostID); !errors.Is(err, ErrUnevaluated) {
		var pending int
		_ = f.s.Pool.QueryRow(ctx, `SELECT count(*) FROM software_versions WHERE distro = $1 AND matcher_version IS NULL`, f.distro).Scan(&pending)
		if err != nil || pending != 0 {
			t.Fatalf("reconcile before match: err = %v with %d unevaluated", err, pending)
		}
		// A dev worker's sweep evaluated them concurrently; fine.
	}

	m := f.matchPush(res)
	if m.Evaluated != 7 {
		t.Fatalf("match: %+v", m)
	}
	// Bookkeeping: kernel mapping and exclusions.
	var n int
	if err := f.s.Pool.QueryRow(ctx, `
		SELECT count(*) FROM software_versions
		WHERE distro = $1 AND matcher_version = $2 AND evaluated_at IS NOT NULL`, f.distro, matcher.Version).Scan(&n); err != nil || n != 7 {
		t.Fatalf("stamped = %d, %v", n, err)
	}
	var src, kr, maxFix *string
	_ = f.s.Pool.QueryRow(ctx, `SELECT match_source, kernel_release, max_fixed_version FROM software_versions WHERE distro = $1 AND name = $2`,
		f.distro, "linux-image-"+k91).Scan(&src, &kr, &maxFix)
	if deref(src) != "linux" || deref(kr) != k91 || deref(maxFix) != "5.15.0-92.102" {
		t.Errorf("kernel image bookkeeping: %v %v %v", deref(src), deref(kr), deref(maxFix))
	}
	_ = f.s.Pool.QueryRow(ctx, `SELECT match_source FROM software_versions WHERE distro = $1 AND name = 'linux-libc-dev'`, f.distro).Scan(&src)
	if src != nil {
		t.Errorf("linux-libc-dev must not be matched, match_source = %v", *src)
	}

	r := f.reconcile()
	if r.RunningKernel != k91 || r.Opened != 4 {
		t.Fatalf("first reconcile: %+v", r)
	}
	fs := f.findings()
	a := fs[findings.DedupKey("swlib", cveA)]
	if a.Status != "open" || a.Installed != "1.0-1" || a.Fixed != "1.0-2" || a.FixChannel != "standard" ||
		!slices.Equal(a.Packages, []string{"libsw1", "swlib-bin"}) || a.Severity != "medium" {
		t.Errorf("finding A (per-CVE record decides severity): %+v", a)
	}
	if b := fs[findings.DedupKey("swlib", cveB)]; b.Status != "open" || b.Severity != "high" {
		t.Errorf("finding B (from the notice): %+v", b)
	}
	if p := fs[findings.DedupKey("swlib", cveP)]; !p.RequiresPro || p.FixChannel != "ubuntu-pro" || p.Fixed != "1.0-3ubuntu0.1~esm1" {
		t.Errorf("finding P (requires Pro): %+v", p)
	}
	k := fs[findings.DedupKey("linux", cveK)]
	if k.Status != "open" || k.Installed != "5.15.0-91.101" || k.Kernel != k91 || k.RunningUnknown ||
		!slices.Equal(k.Packages, []string{"linux-image-" + k91, "linux-modules-" + k91}) {
		t.Errorf("kernel finding (running kernel only): %+v", k)
	}
	if _, ok := fs[findings.DedupKey("linux", cveK88)]; ok {
		t.Error("a CVE only in the non-running kernel must not raise a finding")
	}
	// The non-running kernel is visible as info.
	var running, notRunning, vulns int
	if err := f.s.Pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE is_running), count(*) FILTER (WHERE NOT is_running),
		       COALESCE(sum(vuln_count) FILTER (WHERE NOT is_running), 0)
		FROM host_kernel_packages WHERE host_id = $1`, f.hostID).Scan(&running, &notRunning, &vulns); err != nil {
		t.Fatal(err)
	}
	if running != 2 || notRunning != 1 || vulns != 2 {
		t.Errorf("host_kernel_packages: running %d, not running %d, vulns %d", running, notRunning, vulns)
	}

	// Upgrade swlib to the fixed version: A and B resolve, P stays open.
	swlib2 := []inventory.Item{srcPkg("libsw1", "1.0-2", "swlib", "1.0-2"), srcPkg("swlib-bin", "1.0-2", "swlib", "1.0-2")}
	res = f.pushK(2, k91, append(slices.Clone(swlib2), kernels...)...)
	f.matchPush(res)
	r = f.reconcile()
	st := f.statuses()
	if r.Resolved != 2 || st[findings.DedupKey("swlib", cveA)] != "resolved" || st[findings.DedupKey("swlib", cveB)] != "resolved" ||
		st[findings.DedupKey("swlib", cveP)] != "open" {
		t.Fatalf("upgrade: %+v %v", r, st)
	}
	if p := f.findings()[findings.DedupKey("swlib", cveP)]; p.Installed != "1.0-2" {
		t.Errorf("P installed version not refreshed: %+v", p)
	}

	// Advisory change: a new unfixed CVE for swlib -> drained -> opened.
	f.upsert(f.perCVE(cveC, row("swlib", osv.ChannelStandard, nil, "critical")))
	dr, err := f.s.DrainAdvisoryChanges(ctx, DrainOptions{Distro: f.distro})
	if err != nil {
		t.Fatal(err)
	}
	// Both swlib versions ever interned (1.0-1 is no longer installed, but
	// matches are per version, fleet-wide) gain the CVE.
	if dr.Keys == 0 || len(dr.Changed) != 4 || dr.Kept != 0 {
		t.Fatalf("drain: %+v", dr)
	}
	if left := f.count(`SELECT count(*) FROM advisory_changes WHERE distro = $1`); left != 0 {
		t.Errorf("%d keys left after drain", left)
	}
	hosts, err := f.s.HostsWithSoftware(ctx, dr.Changed)
	if err != nil || !slices.Equal(hosts, []string{f.hostID}) {
		t.Fatalf("hosts = %v, %v", hosts, err)
	}
	if r = f.reconcile(); r.Opened != 1 || f.statuses()[findings.DedupKey("swlib", cveC)] != "open" {
		t.Fatalf("after advisory change: %+v", r)
	}
	// Draining again with nothing dirty changes nothing.
	if dr, _ = f.s.DrainAdvisoryChanges(ctx, DrainOptions{Distro: f.distro}); dr.Keys != 0 {
		t.Errorf("second drain: %+v", dr)
	}

	// Downgrade back: A and B reopen (versions already evaluated, so no
	// match job is needed), first_seen kept.
	res = f.pushK(3, k91, append(slices.Clone(swlib), kernels...)...)
	if len(res.RematchSoftwareIDs()) != 0 {
		t.Errorf("downgrade to known versions interned %v", res.RematchSoftwareIDs())
	}
	r = f.reconcile()
	fs = f.findings()
	if r.Reopened != 2 || fs[findings.DedupKey("swlib", cveA)].ReopenCount != 1 || fs[findings.DedupKey("swlib", cveA)].Status != "open" {
		t.Fatalf("reopen: %+v %+v", r, fs[findings.DedupKey("swlib", cveA)])
	}

	// Reboot into the old kernel (no package change): K88 opens; K stays
	// open, now showing the 88 kernel.
	res = f.pushK(4, k88, append(slices.Clone(swlib), kernels...)...)
	if !res.KernelChanged || res.InventoryChanged() {
		t.Fatalf("reboot push: %+v", res)
	}
	r = f.reconcile()
	fs = f.findings()
	if r.Opened != 1 || fs[findings.DedupKey("linux", cveK88)].Status != "open" ||
		fs[findings.DedupKey("linux", cveK)].Installed != "5.15.0-88.98" {
		t.Fatalf("after reboot into 88: %+v %+v", r, fs)
	}

	// Unknown running kernel (older agent): every installed kernel raises,
	// flagged.
	res = f.pushK(5, "", append(slices.Clone(swlib), kernels...)...)
	if !res.KernelChanged {
		t.Fatal("known -> unknown kernel must count as changed")
	}
	f.reconcile()
	fs = f.findings()
	if !fs[findings.DedupKey("linux", cveK)].RunningUnknown || fs[findings.DedupKey("linux", cveK88)].Status != "open" {
		t.Errorf("unknown kernel fallback: %+v", fs)
	}

	// Back on 91; remove swlib entirely: its findings resolve, K88 resolves.
	res = f.pushK(6, k91, kernels...)
	r = f.reconcile()
	st = f.statuses()
	for _, c := range []string{cveA, cveB, cveP, cveC} {
		if st[findings.DedupKey("swlib", c)] != "resolved" {
			t.Errorf("%s after removal: %s", c, st[findings.DedupKey("swlib", c)])
		}
	}
	if st[findings.DedupKey("linux", cveK88)] != "resolved" || st[findings.DedupKey("linux", cveK)] != "open" {
		t.Errorf("kernel findings back on 91: %v", st)
	}

	// Re-rank: K becomes KEV-listed -> critical, without touching lifecycle.
	since := time.Now().Add(-time.Minute)
	if _, err := f.s.Pool.Exec(ctx, `
		INSERT INTO cves (id, is_kev, epss_score) VALUES ($1, true, 0.9)
		ON CONFLICT (id) DO UPDATE SET is_kev = true, epss_score = 0.9, updated_at = now()`, cveK); err != nil {
		t.Fatal(err)
	}
	rr, err := f.s.RerankFindings(ctx, since)
	if err != nil || rr.Updated < 1 {
		t.Fatalf("rerank: %+v, %v", rr, err)
	}
	if k := f.findings()[findings.DedupKey("linux", cveK)]; k.Severity != "critical" || k.Status != "open" {
		t.Errorf("after rerank: %+v", k)
	}
	if rr, _ = f.s.RerankFindings(ctx, since); rr.Updated != 0 {
		t.Errorf("rerank is not idempotent: %+v", rr)
	}
}

func TestMatchVersionsIsIdempotentAndReportsChanges(t *testing.T) {
	f := newMatchFixture(t)
	ctx := context.Background()
	cve := f.cve()
	f.upsert(f.perCVE(cve, row("swidem", osv.ChannelStandard, sp("2.0-1"), "low")))
	res := f.pushK(1, "", srcPkg("swidem", "1.0-1", "swidem", "1.0-1"))
	ids := res.RematchSoftwareIDs()

	m1, err := f.s.MatchVersions(ctx, ids)
	if err != nil || m1.Matches != 1 {
		t.Fatalf("first: %+v %v", m1, err)
	}
	m2, err := f.s.MatchVersions(ctx, ids)
	if err != nil || len(m2.Changed) != 0 || m2.Matches != 1 {
		t.Fatalf("second evaluation must be a no-op change-wise: %+v %v", m2, err)
	}
	// Advisory now says fixed below the installed version: the match set
	// empties, and it is reported as a change.
	f.upsert(f.perCVE(cve, row("swidem", osv.ChannelStandard, sp("1.0-1"), "low")))
	m3, err := f.s.MatchVersions(ctx, ids)
	if err != nil || len(m3.Changed) != 1 || m3.Matches != 0 {
		t.Fatalf("after fix: %+v %v", m3, err)
	}
	if n := f.count(`SELECT count(*) FROM software_vulnerabilities sw JOIN software_versions sv ON sv.id = sw.software_id WHERE sv.distro = $1`); n != 0 {
		t.Errorf("%d stale matches left", n)
	}
}

func (f *matchFixture) count(q string) int {
	f.t.Helper()
	var n int
	if err := f.s.Pool.QueryRow(context.Background(), q, f.distro).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}
