package store

// image_sbom_vulns (migration 0019): the per-(source, vuln_key) rows
// ScoreImageSBOM persists with its score. Skipped unless
// SW_TEST_DATABASE_URL is set; built on the image fixture.

import (
	"context"
	"slices"
	"testing"
	"time"
)

type imageVulnRow struct {
	Installed, Severity    string
	Rank                   int
	Key                    int64
	Fixed, Channel         *string
	Packages               []string
	SoftwareIDs            []int64
	KEV                    bool
	EPSS, CVSS             *float64
	AdvisoryIDs            []string
	Ecosystem, DistroSever string
}

func (f *imageFixture) sbomVulns(sbomID int64) map[string]imageVulnRow {
	f.t.Helper()
	rows, err := f.s.Pool.Query(context.Background(), `
		SELECT source_package || ':' || vuln_key, installed_version, severity, severity_rank, severity_key,
		       fixed_version, fix_channel, packages, software_ids, is_kev, epss_score::float8,
		       cvss_v3_score::float8, advisory_ids, ecosystem, coalesce(distro_severity, '')
		FROM image_sbom_vulns WHERE sbom_id = $1
	`, sbomID)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]imageVulnRow{}
	for rows.Next() {
		var k string
		var r imageVulnRow
		if err := rows.Scan(&k, &r.Installed, &r.Severity, &r.Rank, &r.Key, &r.Fixed, &r.Channel,
			&r.Packages, &r.SoftwareIDs, &r.KEV, &r.EPSS, &r.CVSS, &r.AdvisoryIDs, &r.Ecosystem,
			&r.DistroSever); err != nil {
			f.t.Fatal(err)
		}
		out[k] = r
	}
	if err := rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	return out
}

func TestImageSBOMVulnsPersisted(t *testing.T) {
	f := newImageFixture(t)
	ctx := context.Background()
	cve1, cve2 := f.cve(), f.cve()
	f.upsert(f.perCVE(cve1, row("openssl", "standard", sp("3.0.2-11"), "high")),
		f.perCVE(cve2, row("zlib", "standard", nil, "medium")))

	// Two openssl binaries from different source versions: the group's
	// installed version is the lower by the deb comparator (3.0.2-9), not
	// by text order (3.0.2-10).
	k := f.image("vulns")
	res := f.list(k, "", SBOMSourceAttestation,
		f.deb("libssl3", "openssl", "3.0.2-10"), f.deb("openssl", "openssl", "3.0.2-9"),
		f.deb("zlib1g", "zlib", "1.2.13-1"), f.deb("bash", "bash", "5.1-6"))
	sc := f.score(res.SBOMID)
	got := f.sbomVulns(res.SBOMID)
	if len(got) != 2 || sc.Score.Vulns != 2 {
		t.Fatalf("rows %v, score %+v", got, sc.Score)
	}
	o := got["openssl:"+cve1]
	if o.Installed != "3.0.2-9" || o.Severity != "high" || o.Rank != 5 || o.Fixed == nil ||
		*o.Fixed != "3.0.2-11" || o.Channel == nil || *o.Channel != "standard" ||
		!slices.Equal(o.Packages, []string{"libssl3", "openssl"}) || len(o.SoftwareIDs) != 2 ||
		o.KEV || o.EPSS != nil || o.CVSS != nil || o.Ecosystem != "deb" || o.DistroSever != "high" ||
		!slices.Equal(o.AdvisoryIDs, []string{"UBUNTU-" + cve1}) {
		t.Errorf("openssl row: %+v", o)
	}
	z := got["zlib:"+cve2]
	if z.Installed != "1.2.13-1" || z.Severity != "medium" || z.Fixed != nil || z.Channel != nil ||
		!slices.Equal(z.Packages, []string{"zlib1g"}) {
		t.Errorf("zlib row: %+v", z)
	}
	// Rows add up to the score.
	if top := max(o.Key, z.Key); top != int64(sc.Score.TopKey) {
		t.Errorf("top key %d, score %d", top, sc.Score.TopKey)
	}

	// Enrichment: re-scoring rewrites the rows with the new assessment.
	if _, err := f.s.Pool.Exec(ctx, `
		INSERT INTO cves (id, is_kev, epss_score, cvss_v3_score) VALUES ($1, true, 0.12345, 9.1)
		ON CONFLICT (id) DO UPDATE SET is_kev = true, epss_score = 0.12345, cvss_v3_score = 9.1, updated_at = now()`,
		cve1); err != nil {
		t.Fatal(err)
	}
	f.score(res.SBOMID)
	o = f.sbomVulns(res.SBOMID)["openssl:"+cve1]
	if !o.KEV || o.Severity != "critical" || o.Rank != 6 || o.EPSS == nil || *o.EPSS != 0.12345 ||
		o.CVSS == nil || *o.CVSS != 9.1 {
		t.Errorf("openssl after KEV: %+v", o)
	}
	// The key equals what a vulnerable_image finding of the same group gets.
	f.onHost(f.hostID, k, "x:1")
	f.container(f.hostID, k, "x", "running", 1)
	f.reconcileHost(f.hostID)
	var fkey int64
	if err := f.s.Pool.QueryRow(ctx, `
		SELECT severity_key FROM findings WHERE host_id = $1 AND kind = 'vulnerable_image' AND vuln_key = $2
	`, f.hostID, cve1).Scan(&fkey); err != nil || fkey != o.Key {
		t.Errorf("finding key %d (%v), row key %d", fkey, err, o.Key)
	}

	// A rewritten list replaces the rows as a whole (zlib gone).
	time.Sleep(10 * time.Millisecond) // updated_at must move past the old score
	res2 := f.list(k, "", SBOMSourceAttestation,
		f.deb("libssl3", "openssl", "3.0.2-10"), f.deb("bash", "bash", "5.1-6"))
	if res2.SBOMID != res.SBOMID {
		t.Fatalf("list id changed: %d -> %d", res.SBOMID, res2.SBOMID)
	}
	got = f.sbomVulns(res.SBOMID)
	if len(got) != 1 || got["openssl:"+cve1].Installed != "3.0.2-10" ||
		!slices.Equal(got["openssl:"+cve1].Packages, []string{"libssl3"}) {
		t.Errorf("after rewrite: %v", got)
	}

	// Backfill: a score counting vulnerabilities without rows (scored
	// before migration 0019) is stale until re-scored.
	if _, err := f.s.Pool.Exec(ctx, `DELETE FROM image_sbom_vulns WHERE sbom_id = $1`, res.SBOMID); err != nil {
		t.Fatal(err)
	}
	stale, err := f.s.StaleImageScores(ctx, 100000)
	if err != nil || !slices.Contains(stale, res.SBOMID) {
		t.Fatalf("score without rows not stale: %v %v", stale, err)
	}
	f.score(res.SBOMID)
	stale, err = f.s.StaleImageScores(ctx, 100000)
	if err != nil || slices.Contains(stale, res.SBOMID) || len(f.sbomVulns(res.SBOMID)) != 1 {
		t.Errorf("after re-score: stale %v %v", stale, err)
	}
}
