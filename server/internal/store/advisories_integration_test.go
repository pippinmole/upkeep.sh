package store

// Integration tests for the advisory store against a real, fully migrated
// Postgres; skipped unless SW_TEST_DATABASE_URL is set (see
// inventory_integration_test.go). Every advisory id, distro and CVE id is
// unique to the test run and deleted afterwards, so the tests are safe
// against a dev database that also holds real synced data.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/cvefeeds"
	"github.com/pippinmole/upkeep.sh/server/internal/osv"
)

type advFixture struct {
	t      *testing.T
	s      *Store
	tag    string // unique; used as source, distro and id prefix
	cve    string
	mod    time.Time
	hashes int
}

func newAdvFixture(t *testing.T) *advFixture {
	t.Helper()
	dsn := os.Getenv("SW_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SW_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	f := &advFixture{
		t: t, s: s, tag: "swtest-" + hex.EncodeToString(b),
		cve: fmt.Sprintf("CVE-1900-%d", 100000+int(b[0])<<16|int(b[1])<<8|int(b[2])),
		mod: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = s.Pool.Exec(ctx, `DELETE FROM advisories WHERE source = $1`, f.tag)
		_, _ = s.Pool.Exec(ctx, `DELETE FROM advisory_changes WHERE distro = $1`, f.tag)
		_, _ = s.Pool.Exec(ctx, `DELETE FROM cves WHERE id = $1`, f.cve)
		s.Close()
	})
	return f
}

func sp(s string) *string { return &s }

// adv builds an advisory; each call gets a fresh content hash.
func (f *advFixture) adv(id string, rows ...osv.AffectedRow) osv.Advisory {
	f.hashes++
	for i := range rows {
		rows[i].Distro = f.tag
		if rows[i].Status == "" {
			rows[i].Status = "unfixed"
			if rows[i].FixedVersion != nil {
				rows[i].Status = "fixed"
			}
		}
		if rows[i].Channel == "" {
			rows[i].Channel = osv.ChannelStandard
		}
		rows[i].Ecosystem = "Test:1"
	}
	return osv.Advisory{
		ID: f.tag + "-" + id, Source: f.tag, VulnKey: f.cve, CVEIDs: []string{f.cve},
		Aliases: []string{}, Upstream: []string{f.cve}, Related: []string{},
		Summary: "s", Details: "d", Modified: f.mod, Raw: []byte(`{"id":"x"}`),
		ContentHash: fmt.Sprintf("h%d", f.hashes), Affected: rows,
	}
}

func (f *advFixture) dirtyKeys() []string {
	f.t.Helper()
	rows, err := f.s.Pool.Query(context.Background(),
		`SELECT release || '/' || source_package FROM advisory_changes WHERE distro = $1 ORDER BY 1`, f.tag)
	if err != nil {
		f.t.Fatal(err)
	}
	var out []string
	for rows.Next() {
		var k string
		_ = rows.Scan(&k)
		out = append(out, k)
	}
	return out
}

func (f *advFixture) clearDirty() {
	_, _ = f.s.Pool.Exec(context.Background(), `DELETE FROM advisory_changes WHERE distro = $1`, f.tag)
}

func (f *advFixture) count(q string) int {
	f.t.Helper()
	var n int
	if err := f.s.Pool.QueryRow(context.Background(), q, f.tag).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func TestUpsertAdvisoriesDirtyTracking(t *testing.T) {
	f := newAdvFixture(t)
	ctx := context.Background()

	a := f.adv("A",
		osv.AffectedRow{Release: "r1", SourcePackage: "openssl", Introduced: "0", FixedVersion: sp("3.0.2-1")},
		osv.AffectedRow{Release: "r1", SourcePackage: "curl", Introduced: "0"},
	)
	res, err := f.s.UpsertAdvisories(ctx, []osv.Advisory{a})
	if err != nil {
		t.Fatal(err)
	}
	if res.Written != 1 || res.Rows != 2 || res.Dirty != 2 {
		t.Fatalf("first write = %+v", res)
	}
	if got := f.dirtyKeys(); !slices.Equal(got, []string{"r1/curl", "r1/openssl"}) {
		t.Fatalf("dirty = %v", got)
	}
	f.clearDirty()

	// Same content hash: nothing written, nothing dirtied.
	res, err = f.s.UpsertAdvisories(ctx, []osv.Advisory{a})
	if err != nil || res.Unchanged != 1 || res.Written != 0 || len(f.dirtyKeys()) != 0 {
		t.Fatalf("re-upsert = %+v, %v, dirty %v", res, err, f.dirtyKeys())
	}

	// New hash, only curl's row differs (now fixed): only curl is dirty.
	a2 := f.adv("A",
		osv.AffectedRow{Release: "r1", SourcePackage: "openssl", Introduced: "0", FixedVersion: sp("3.0.2-1")},
		osv.AffectedRow{Release: "r1", SourcePackage: "curl", Introduced: "0", FixedVersion: sp("7.81.0-1")},
	)
	res, err = f.s.UpsertAdvisories(ctx, []osv.Advisory{a2})
	if err != nil || res.Written != 1 || res.Dirty != 1 {
		t.Fatalf("update = %+v, %v", res, err)
	}
	if got := f.dirtyKeys(); !slices.Equal(got, []string{"r1/curl"}) {
		t.Fatalf("dirty after update = %v", got)
	}
	f.clearDirty()

	// Metadata-only change (new hash, same rows): written, nothing dirty.
	a3 := a2
	a3.Summary = "changed"
	a3.ContentHash = "meta"
	res, err = f.s.UpsertAdvisories(ctx, []osv.Advisory{a3})
	if err != nil || res.Written != 1 || res.Dirty != 0 || len(f.dirtyKeys()) != 0 {
		t.Fatalf("metadata update = %+v, %v", res, err)
	}

	// Withdrawal = no rows: both packages dirty, rows gone, advisory kept.
	wd := f.adv("A")
	now := time.Now().UTC()
	wd.Withdrawn = &now
	if res, err = f.s.UpsertAdvisories(ctx, []osv.Advisory{wd}); err != nil || res.Dirty != 2 {
		t.Fatalf("withdraw = %+v, %v", res, err)
	}
	if n := f.count(`SELECT count(*) FROM advisory_affected WHERE distro = $1`); n != 0 {
		t.Fatalf("withdrawn advisory still has %d rows", n)
	}
	if n := f.count(`SELECT count(*) FROM advisories WHERE source = $1 AND withdrawn_at IS NOT NULL`); n != 1 {
		t.Fatalf("withdrawn advisories = %d", n)
	}
}

func TestDeleteAdvisoriesMarksDirty(t *testing.T) {
	f := newAdvFixture(t)
	ctx := context.Background()
	advs := []osv.Advisory{
		f.adv("A", osv.AffectedRow{Release: "r1", SourcePackage: "pa", Introduced: "0"}),
		f.adv("B", osv.AffectedRow{Release: "r1", SourcePackage: "pb", Introduced: "0"}),
		f.adv("C", osv.AffectedRow{Release: "r2", SourcePackage: "pc", Introduced: "0"}),
	}
	if _, err := f.s.UpsertAdvisories(ctx, advs); err != nil {
		t.Fatal(err)
	}
	f.clearDirty()

	n, err := f.s.DeleteAdvisories(ctx, f.tag, []string{f.tag + "-A", f.tag + "-missing"})
	if err != nil || n != 1 {
		t.Fatalf("delete = %d, %v", n, err)
	}
	if got := f.dirtyKeys(); !slices.Equal(got, []string{"r1/pa"}) {
		t.Fatalf("dirty = %v", got)
	}
	f.clearDirty()

	// Full-sync sweep: keep only C.
	n, err = f.s.DeleteAdvisoriesExcept(ctx, f.tag, []string{f.tag + "-C"})
	if err != nil || n != 1 {
		t.Fatalf("delete except = %d, %v", n, err)
	}
	if got := f.dirtyKeys(); !slices.Equal(got, []string{"r1/pb"}) {
		t.Fatalf("dirty = %v", got)
	}
	if n := f.count(`SELECT count(*) FROM advisory_affected WHERE distro = $1`); n != 1 {
		t.Fatalf("remaining rows = %d, want 1 (cascade)", n)
	}
}

func TestUpsertAdvisoriesCVSS(t *testing.T) {
	f := newAdvFixture(t)
	ctx := context.Background()
	a := f.adv("A", osv.AffectedRow{Release: "r1", SourcePackage: "p", Introduced: "0"})
	a.CVSSv3Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	if _, err := f.s.UpsertAdvisories(ctx, []osv.Advisory{a}); err != nil {
		t.Fatal(err)
	}
	var score float64
	var vec, desc string
	if err := f.s.Pool.QueryRow(ctx, `SELECT cvss_v3_score::float8, cvss_v3_vector, description FROM cves WHERE id = $1`, f.cve).
		Scan(&score, &vec, &desc); err != nil {
		t.Fatal(err)
	}
	if score != 9.8 || vec != a.CVSSv3Vector || desc != "d" {
		t.Errorf("cves row = %v %q %q", score, vec, desc)
	}
}

func TestFeedState(t *testing.T) {
	f := newAdvFixture(t)
	ctx := context.Background()
	feed := f.tag
	t.Cleanup(func() {
		_, _ = f.s.Pool.Exec(context.Background(), `DELETE FROM feed_sync_state WHERE feed = $1`, feed)
	})

	st, err := f.s.GetFeedState(ctx, feed)
	if err != nil || st.LastSuccessAt != nil || st.Cursor != "" {
		t.Fatalf("empty state = %+v, %v", st, err)
	}
	if err := f.s.FeedSucceeded(ctx, feed, FeedSuccess{Cursor: "c1", ETag: "e1", ConfigHash: "h1", Full: true}); err != nil {
		t.Fatal(err)
	}
	// Empty fields keep stored values; a failure records the error only.
	if err := f.s.FeedSucceeded(ctx, feed, FeedSuccess{Cursor: "c2"}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.FeedFailed(ctx, feed, errors.New("boom")); err != nil {
		t.Fatal(err)
	}
	st, err = f.s.GetFeedState(ctx, feed)
	if err != nil || st.Cursor != "c2" || st.ETag != "e1" || st.ConfigHash != "h1" || st.LastFullSyncAt == nil {
		t.Fatalf("state = %+v, %v", st, err)
	}
}

func TestApplyEPSS(t *testing.T) {
	f := newAdvFixture(t)
	ctx := context.Background()
	// Real rows (CVE-1999-000[1-4]) with today's real values, so running
	// this against a synced dev database changes nothing there.
	fh, err := os.Open("../cvefeeds/testdata/epss.csv.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	r, err := cvefeeds.NewEPSSReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	rows, _, err := f.s.ApplyEPSS(ctx, r)
	if err != nil || rows != 4 {
		t.Fatalf("rows = %d, %v", rows, err)
	}
	var score, pct float64
	if err := f.s.Pool.QueryRow(ctx, `SELECT epss_score::float8, epss_percentile::float8 FROM cves WHERE id = 'CVE-1999-0002'`).
		Scan(&score, &pct); err != nil {
		t.Fatal(err)
	}
	if score != 0.27858 || pct != 0.98033 {
		t.Errorf("CVE-1999-0002 = %v %v", score, pct)
	}
}
