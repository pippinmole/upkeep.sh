package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/osv"
)

// npm packages from an image list, matched against GHSA-style advisory
// rows (distro ”, release 'npm', osv/language.go) with node-semver
// ordering and OSV range semantics, end to end through the store. The
// fixture's packages are "@<tag>/name", so their advisory keys are unique.
func TestNpmMatching(t *testing.T) {
	f := newSBOMFixture(t)
	ctx := context.Background()
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	ghsaOnly := "GHSA-" + hex.EncodeToString(b[:2]) + "-" + hex.EncodeToString(b[2:]) + "-test"
	cve := fmt.Sprintf("CVE-1903-%d", 1000000+int(b[0])<<16|int(b[1])<<8|int(b[2]))
	t.Cleanup(func() {
		_, _ = f.s.Pool.Exec(context.Background(), `DELETE FROM advisories WHERE source = $1`, f.tag)
		_, _ = f.s.Pool.Exec(context.Background(), `DELETE FROM advisory_changes WHERE distro = '' AND source_package LIKE $1`, "@"+f.tag+"/%")
		_, _ = f.s.Pool.Exec(context.Background(), `DELETE FROM cves WHERE id = ANY($1)`, []string{ghsaOnly, cve})
	})
	name := func(n string) string { return "@" + f.tag + "/" + n }
	hashes := 0
	ghsa := func(id string, cves []string, sev, vector string, rows ...osv.AffectedRow) osv.Advisory {
		hashes++
		key := id
		if cves == nil {
			cves = []string{}
		}
		if len(cves) == 1 {
			key = cves[0]
		}
		for i := range rows {
			rows[i].Distro, rows[i].Release, rows[i].Channel, rows[i].Ecosystem = "", "npm", osv.ChannelStandard, "npm"
			rows[i].DistroSeverity = &sev
			rows[i].Status = "unfixed"
			if rows[i].FixedVersion != nil {
				rows[i].Status = "fixed"
			}
		}
		return osv.Advisory{
			ID: id, Source: f.tag, VulnKey: key, CVEIDs: cves,
			Aliases: cves, Upstream: []string{}, Related: []string{}, Details: "test " + id,
			Modified: time.Now().UTC(), Raw: []byte(`{}`), ContentHash: fmt.Sprintf("%s-h%d", f.tag, hashes),
			Affected: rows, CVSSv3Vector: vector, CVSSIfMissing: key != id,
		}
	}
	rng := func(pkg, introduced string, fixed, last *string) osv.AffectedRow {
		return osv.AffectedRow{SourcePackage: name(pkg), Introduced: introduced, FixedVersion: fixed, LastAffected: last}
	}
	upsert := func(advs ...osv.Advisory) {
		t.Helper()
		if _, err := f.s.UpsertAdvisories(ctx, advs); err != nil {
			t.Fatal(err)
		}
	}
	matches := func() map[string][]string {
		t.Helper()
		rows, err := f.s.Pool.Query(ctx, `
			SELECT s.name, v.vuln_key || ' ' || COALESCE(v.fixed_version, '-') || ' ' || COALESCE(v.distro_severity, '-')
			FROM software_versions s JOIN software_vulnerabilities v ON v.software_id = s.id
			WHERE s.ecosystem = 'npm' AND s.name LIKE $1 ORDER BY 1, 2`, "@"+f.tag+"/%")
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

	// Two branches of one record: [0, 3.10.2) and [4.0.0, 4.17.21).
	upsert(
		ghsa("GHSA-"+f.tag[7:11]+"-aaaa-bbbb", []string{cve}, "high", "",
			rng("lodash", "0", sp("3.10.2"), nil), rng("lodash", "4.0.0", sp("4.17.21"), nil)),
		// No CVE: keyed by the GHSA, whose CVSS gets a cves row.
		ghsa(ghsaOnly, nil, "moderate", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			rng("minimist", "0", nil, sp("1.2.5"))),
	)

	key := f.image("node")
	res := f.write(key, "", SBOMSourceAttestation,
		f.npm("lodash", "4.17.20", "/app/node_modules/lodash/package.json"),
		f.npm("minimist", "1.2.5"),
		f.npm("left-pad", "1.3.0"),
	)
	m, err := f.s.MatchVersions(ctx, res.RematchSoftwareIDs())
	if err != nil {
		t.Fatal(err)
	}
	if m.Evaluated != 3 || m.BadVersions != 0 {
		t.Fatalf("match: %+v", m)
	}
	got := matches()
	if len(got) != 2 || len(got[name("lodash")]) != 1 || got[name("lodash")][0] != cve+" 4.17.21 high" ||
		len(got[name("minimist")]) != 1 || got[name("minimist")][0] != ghsaOnly+" - moderate" {
		t.Fatalf("matches = %v", got)
	}
	var score *float64
	if err := f.s.Pool.QueryRow(ctx, `SELECT cvss_v3_score::float8 FROM cves WHERE id = $1`, ghsaOnly).Scan(&score); err != nil || score == nil || *score != 7.5 {
		t.Errorf("GHSA cvss = %v (%v)", score, err)
	}

	// The list is fully assessed (language packages have no release) and
	// the GHSA-only finding ranks by its GitHub severity.
	sc, err := f.s.ScoreImageSBOM(ctx, res.SBOMID)
	if err != nil || !sc.Found || sc.Pending != 0 {
		t.Fatalf("score: %+v %v", sc, err)
	}
	var notAssessed, vulns, medium, high int
	if err := f.s.Pool.QueryRow(ctx, `SELECT not_assessed_count, vuln_count, medium_count, high_count
		FROM image_sbom_scores WHERE sbom_id = $1`, res.SBOMID).Scan(&notAssessed, &vulns, &medium, &high); err != nil {
		t.Fatal(err)
	}
	if notAssessed != 0 || vulns != 2 || medium != 1 || high != 1 {
		t.Errorf("score: not assessed %d, vulns %d, medium %d, high %d", notAssessed, vulns, medium, high)
	}

	// The advisory moves the lodash fix below the installed version, via
	// the advisory_changes drain of the ('', 'npm', name) key.
	upsert(ghsa("GHSA-"+f.tag[7:11]+"-aaaa-bbbb", []string{cve}, "high", "",
		rng("lodash", "0", sp("3.10.2"), nil), rng("lodash", "4.0.0", sp("4.17.20"), nil)))
	if _, err := f.s.DrainAdvisoryChanges(ctx, DrainOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := matches(); len(got[name("lodash")]) != 0 || len(got[name("minimist")]) != 1 {
		t.Fatalf("after fix at 4.17.20: %v", got)
	}
	var left int
	if err := f.s.Pool.QueryRow(ctx, `SELECT count(*) FROM advisory_changes WHERE distro = '' AND source_package LIKE $1`,
		"@"+f.tag+"/%").Scan(&left); err != nil || left != 0 {
		t.Errorf("advisory_changes left: %d (%v)", left, err)
	}
}
