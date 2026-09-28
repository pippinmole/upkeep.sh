package store

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/osv"
	"github.com/pippinmole/upkeep.sh/server/internal/purl"
)

// apk packages from an image list, matched against Alpine-style advisory
// rows with the apk comparator, end to end through the store. The
// fixture's unique tag stands in for the distro "alpine" (advisory rows,
// software_versions and advisory_changes are all scoped to it), release
// "3.22" as purl.ReleaseFor keys Alpine branches.
func TestApkMatching(t *testing.T) {
	f := newSBOMFixture(t)
	f.osr = purl.OSRelease{ID: f.tag, VersionID: "3.22"}
	ctx := context.Background()
	var cves []string
	cve := func() string {
		b := make([]byte, 3)
		_, _ = rand.Read(b)
		id := fmt.Sprintf("CVE-1902-%d", 1000000+int(b[0])<<16|int(b[1])<<8|int(b[2]))
		cves = append(cves, id)
		return id
	}
	t.Cleanup(func() {
		_, _ = f.s.Pool.Exec(context.Background(), `DELETE FROM advisories WHERE source = $1`, f.tag)
		_, _ = f.s.Pool.Exec(context.Background(), `DELETE FROM advisory_changes WHERE distro = $1`, f.tag)
		_, _ = f.s.Pool.Exec(context.Background(), `DELETE FROM cves WHERE id = ANY($1)`, cves)
	})
	hashes := 0
	// alpineCVE is an ALPINE-CVE-* record with one row per (source,
	// introduced, fixed).
	alpineCVE := func(id string, rows ...osv.AffectedRow) osv.Advisory {
		hashes++
		for i := range rows {
			rows[i].Distro, rows[i].Release, rows[i].Channel, rows[i].Ecosystem = f.tag, "3.22", osv.ChannelStandard, "Alpine:v3.22"
			rows[i].Status = "unfixed"
			if rows[i].FixedVersion != nil {
				rows[i].Status = "fixed"
			}
		}
		return osv.Advisory{
			ID: "ALPINE-" + id, Source: f.tag, VulnKey: id, CVEIDs: []string{id},
			Aliases: []string{}, Upstream: []string{id}, Related: []string{},
			Modified: time.Now().UTC(), Raw: []byte(`{}`), ContentHash: fmt.Sprintf("%s-h%d", f.tag, hashes), Affected: rows,
		}
	}
	affected := func(src, introduced string, fixed *string) osv.AffectedRow {
		return osv.AffectedRow{SourcePackage: src, Introduced: introduced, FixedVersion: fixed}
	}
	upsert := func(advs ...osv.Advisory) {
		t.Helper()
		if _, err := f.s.UpsertAdvisories(ctx, advs); err != nil {
			t.Fatal(err)
		}
	}
	// matches returns name -> "vuln_key fixed" of every current match.
	matches := func() map[string][]string {
		t.Helper()
		rows, err := f.s.Pool.Query(ctx, `
			SELECT sv.name, sv.vuln_key || ' ' || COALESCE(sv.fixed_version, '-')
			FROM (SELECT s.name, v.vuln_key, v.fixed_version FROM software_versions s
			      JOIN software_vulnerabilities v ON v.software_id = s.id
			      WHERE s.distro = $1) sv ORDER BY 1, 2`, f.tag)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string][]string{}
		for rows.Next() {
			var n, m string
			if err := rows.Scan(&n, &m); err != nil {
				t.Fatal(err)
			}
			out[n] = append(out[n], m)
		}
		return out
	}
	drain := func() {
		t.Helper()
		if _, err := f.s.DrainAdvisoryChanges(ctx, DrainOptions{Distro: f.tag}); err != nil {
			t.Fatal(err)
		}
	}

	opensslCVE, oldCVE, curlCVE, busyboxCVE := cve(), cve(), cve(), cve()
	upsert(
		// Upstream-only introduced ("3.0.0" < every 3.0.0-rN).
		alpineCVE(opensslCVE, affected("openssl", "3.0.0", sp("3.3.2-r0"))),
		// Already fixed at the installed version.
		alpineCVE(oldCVE, affected("openssl", "0", sp("3.3.1-r0"))),
		// apk: 8.10.0-r0 is newer than its _rc1 (dpkg would say older).
		alpineCVE(curlCVE, affected("curl", "0", sp("8.10.0_rc1-r0"))),
		// -r29 > -r3 numerically.
		alpineCVE(busyboxCVE, affected("busybox", "0", sp("1.36.1-r3"))),
	)

	key := f.image("alpine")
	res := f.write(key, "", SBOMSourceAttestation,
		f.pkg("pkg:apk/alpine/libcrypto3@3.3.1-r0?arch=x86_64&upstream=openssl"),
		f.pkg("pkg:apk/alpine/libssl3@3.3.1-r0?arch=x86_64&upstream=openssl"),
		f.pkg("pkg:apk/alpine/curl@8.10.0-r0?arch=x86_64"),
		f.pkg("pkg:apk/alpine/busybox@1.36.1-r29?arch=x86_64"),
	)
	m, err := f.s.MatchVersions(ctx, res.RematchSoftwareIDs())
	if err != nil {
		t.Fatal(err)
	}
	if m.Evaluated != 4 || m.BadVersions != 0 {
		t.Fatalf("match: %+v", m)
	}
	want := opensslCVE + " 3.3.2-r0"
	got := matches()
	if len(got) != 2 || len(got["libcrypto3"]) != 1 || got["libcrypto3"][0] != want || len(got["libssl3"]) != 1 || got["libssl3"][0] != want {
		t.Fatalf("matches = %v, want libcrypto3/libssl3: %s", got, want)
	}
	var src, maxFix string
	if err := f.s.Pool.QueryRow(ctx, `SELECT match_source, max_fixed_version FROM software_versions
		WHERE distro = $1 AND name = 'libcrypto3'`, f.tag).Scan(&src, &maxFix); err != nil || src != "openssl" || maxFix != "3.3.2-r0" {
		t.Errorf("libcrypto3 match_source/max_fixed = %q/%q (%v)", src, maxFix, err)
	}

	// The advisory is corrected to the installed revision: unmatched.
	upsert(alpineCVE(opensslCVE, affected("openssl", "3.0.0", sp("3.3.1-r0"))))
	drain()
	if got := matches(); len(got) != 0 {
		t.Fatalf("after fix at -r0: %v", got)
	}
	// ... and to a later revision of the same version: matched again.
	upsert(alpineCVE(opensslCVE, affected("openssl", "3.0.0", sp("3.3.1-r1"))))
	drain()
	if got := matches(); len(got["libcrypto3"]) != 1 || got["libcrypto3"][0] != opensslCVE+" 3.3.1-r1" {
		t.Fatalf("after fix at -r1: %v", got)
	}
	// Introduced moves above the installed version: out of range.
	upsert(alpineCVE(opensslCVE, affected("openssl", "3.3.1-r1", sp("3.3.2-r0"))))
	drain()
	if got := matches(); len(got) != 0 {
		t.Fatalf("below introduced: %v", got)
	}
}
