package store

// vulnerable_image findings and image scores (migration 0015) against a
// real database: skipped unless SW_TEST_DATABASE_URL is set. Built on the
// matcher fixture (its own user, host, distro tag and advisories); the
// images, lists and second user are this file's and are deleted
// afterwards.

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/findings"
	"github.com/pippinmole/upkeep.sh/server/internal/inventory"
	"github.com/pippinmole/upkeep.sh/server/internal/purl"
)

type imageFixture struct {
	*matchFixture
	userU, userV string
	hostV        string
	images       []string
	containerN   int
}

func newImageFixture(t *testing.T) *imageFixture {
	f := &imageFixture{matchFixture: newMatchFixture(t)}
	ctx := context.Background()
	if err := f.s.Pool.QueryRow(ctx, `SELECT user_id FROM hosts WHERE id = $1`, f.hostID).Scan(&f.userU); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Pool.QueryRow(ctx, `INSERT INTO users (email) VALUES ($1) RETURNING id`,
		f.distro+"-v@test.invalid").Scan(&f.userV); err != nil {
		t.Fatal(err)
	}
	var err error
	if f.hostV, err = f.s.CreateHost(ctx, f.userV, f.distro+"-v"); err != nil {
		t.Fatal(err)
	}
	// Registered after the match fixture's cleanups, so it runs first
	// (LIFO): findings / ranges go with the users, lists with the images.
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = f.s.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, f.userV)
		_, _ = f.s.Pool.Exec(ctx, `DELETE FROM host_containers WHERE host_id = $1`, f.hostID)
		_, _ = f.s.Pool.Exec(ctx, `DELETE FROM host_images WHERE host_id = $1`, f.hostID)
		_, _ = f.s.Pool.Exec(ctx, `DELETE FROM image_sbom_state WHERE image_id = ANY($1)`, f.images)
		_, _ = f.s.Pool.Exec(ctx, `DELETE FROM container_images WHERE image_id = ANY($1)`, f.images)
	})
	return f
}

// image interns a container_images key unique to this run.
func (f *imageFixture) image(n string) ImageKey {
	f.t.Helper()
	k := ImageKey{ImageID: "sha256:" + f.distro + "-" + n, OS: "linux", Arch: "amd64"}
	if _, err := f.s.Pool.Exec(context.Background(),
		`INSERT INTO container_images (image_id, os, arch, variant) VALUES ($1, $2, $3, $4)`,
		k.ImageID, k.OS, k.Arch, k.Variant); err != nil {
		f.t.Fatal(err)
	}
	f.images = append(f.images, k.ImageID)
	return k
}

// onHost opens a host_images range for key on host, tagged ref.
func (f *imageFixture) onHost(host string, k ImageKey, ref string) {
	f.t.Helper()
	if _, err := f.s.Pool.Exec(context.Background(), `
		INSERT INTO host_images (host_id, image_id, repo_tags, os, arch, variant, row_key, row_hash, detail_hash, live_hash, first_seen_at)
		VALUES ($1, $2, ARRAY[$3], $4, $5, $6, $2, 'h', 'd', 'l', $7)
	`, host, k.ImageID, ref, k.OS, k.Arch, k.Variant, f.t0); err != nil {
		f.t.Fatal(err)
	}
}

// container opens a host_containers range running image k; returns its id.
func (f *imageFixture) container(host string, k ImageKey, name, state string, minute int) string {
	f.t.Helper()
	f.containerN++
	id := k.ImageID[len(k.ImageID)-6:] + name + string(rune('a'+f.containerN))
	if _, err := f.s.Pool.Exec(context.Background(), `
		INSERT INTO host_containers (host_id, container_id, name, image_id, state, row_key, row_hash, detail_hash, live_hash, first_seen_at)
		VALUES ($1, $2, $3, $4, $5, $2, 'h', 'd', 'l', $6)
	`, host, id, name, k.ImageID, state, f.t0.Add(time.Duration(minute)*time.Minute)); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *imageFixture) removeContainer(host, id string, minute int) {
	f.t.Helper()
	if _, err := f.s.Pool.Exec(context.Background(), `
		UPDATE host_containers SET removed_at = $3 WHERE host_id = $1 AND container_id = $2 AND removed_at IS NULL
	`, host, id, f.t0.Add(time.Duration(minute)*time.Minute)); err != nil {
		f.t.Fatal(err)
	}
}

// deb is an image package in the fixture's distro, release jammy (where
// its advisories are).
func (f *imageFixture) deb(name, source, version string) ImagePackage {
	return ImagePackage{Package: purl.Package{Ecosystem: "deb", Distro: f.distro, Release: "jammy", KnownType: true,
		Item: inventory.Item{Name: name, Version: version, Arch: "amd64", Source: source, SourceVersion: version}}}
}

// list writes a package list and runs what its jobs would: match the new
// versions, then score it.
func (f *imageFixture) list(k ImageKey, owner, source string, pkgs ...ImagePackage) ImageSBOMResult {
	f.t.Helper()
	ctx := context.Background()
	res, err := f.s.WriteImageSBOM(ctx, ImageSBOMInput{Key: k, OwnerUserID: owner, Source: source,
		OS: purl.OSRelease{ID: f.distro}, Release: "jammy", Packages: pkgs})
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.s.MatchVersions(ctx, res.RematchSoftwareIDs()); err != nil {
		f.t.Fatal(err)
	}
	f.score(res.SBOMID)
	return res
}

func (f *imageFixture) score(sbomID int64) ScoreResult {
	f.t.Helper()
	r, err := f.s.ScoreImageSBOM(context.Background(), sbomID)
	if err != nil || !r.Found || r.Pending != 0 {
		f.t.Fatalf("score %d: %+v %v", sbomID, r, err)
	}
	return r
}

func (f *imageFixture) reconcileHost(host string) ReconcileResult {
	f.t.Helper()
	r, err := f.s.ReconcileHostFindings(context.Background(), host)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

type imageFindingRow struct {
	Status, Severity, ImageOS string
	Refs, Containers          []string
	Packages                  []string
	ReopenCount               int
}

func (f *imageFixture) imageFindings(host string) map[string]imageFindingRow {
	f.t.Helper()
	rows, err := f.s.Pool.Query(context.Background(), `
		SELECT dedup_key, status, severity, image_os, image_refs, container_names, packages, reopen_count
		FROM findings WHERE host_id = $1 AND kind = 'vulnerable_image'
	`, host)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]imageFindingRow{}
	for rows.Next() {
		var k string
		var r imageFindingRow
		if err := rows.Scan(&k, &r.Status, &r.Severity, &r.ImageOS, &r.Refs, &r.Containers, &r.Packages, &r.ReopenCount); err != nil {
			f.t.Fatal(err)
		}
		out[k] = r
	}
	return out
}

func (f *imageFixture) scoreOf(user string, k ImageKey) ImageScore {
	f.t.Helper()
	s, err := f.s.ImageScoreOf(context.Background(), user, k)
	if err != nil || s == nil {
		f.t.Fatalf("score of %s: %v %v", k.ImageID, s, err)
	}
	return *s
}

func TestImageFindingsLifecycle(t *testing.T) {
	f := newImageFixture(t)
	ctx := context.Background()
	cve1, cve2 := f.cve(), f.cve()
	f.upsert(f.perCVE(cve1, row("openssl", "standard", sp("3.0.2-2"), "high")))

	used, unused := f.image("used"), f.image("unused")
	f.onHost(f.hostID, used, "nginx:1.27")
	f.onHost(f.hostID, unused, "old:1")
	f.onHost(f.hostV, used, "nginx:latest")
	web := f.container(f.hostID, used, "web", "exited", 1) // any state counts
	f.container(f.hostV, used, "proxy", "running", 1)
	pkgs := []ImagePackage{f.deb("libssl3", "openssl", "3.0.2-1"), f.deb("openssl", "openssl", "3.0.2-1"),
		f.deb("zlib1g", "zlib", "1.2.13-1")}
	f.list(used, "", SBOMSourceAttestation, pkgs...)
	unusedList := f.list(unused, "", SBOMSourceAttestation, pkgs...)

	// Host package findings are untouched by images (none installed).
	res := f.reconcileHost(f.hostID)
	key1 := findings.ImageDedupKey(used.ImageID, "openssl", cve1)
	got := f.imageFindings(f.hostID)
	if res.Images != 1 || res.Opened != 1 || len(got) != 1 || len(f.findings()) != 0 {
		t.Fatalf("first reconcile: %+v, image findings %v", res, got)
	}
	g := got[key1]
	if g.Status != "open" || g.Severity != "high" || g.ImageOS != "linux" ||
		!slices.Equal(g.Refs, []string{"nginx:1.27"}) || !slices.Equal(g.Containers, []string{"web"}) ||
		!slices.Equal(g.Packages, []string{"libssl3", "openssl"}) {
		t.Errorf("image finding: %+v", g)
	}
	// The other user's host runs the same image under its own tag.
	f.reconcileHost(f.hostV)
	if gv := f.imageFindings(f.hostV); len(gv) != 1 || !slices.Equal(gv[key1].Refs, []string{"nginx:latest"}) ||
		!slices.Equal(gv[key1].Containers, []string{"proxy"}) {
		t.Errorf("user V's host: %v", gv)
	}

	// The unused image: no findings, but a score. The fixture's distro is
	// not a covered one, so every package counts as not assessed.
	sc := f.scoreOf(f.userU, unused)
	if sc.ListStatus != SBOMStatusOK || !sc.Scored || *sc.Vulns != 1 || *sc.WorstSeverity != "high" ||
		*sc.High != 1 || *sc.Packages != 3 || *sc.NotAssessed != 3 || sc.Clean() || *sc.SBOMID != unusedList.SBOMID {
		t.Errorf("unused image score: %+v", sc)
	}
	host, err := f.s.HostImageScores(ctx, f.hostID)
	if err != nil || len(host) != 2 {
		t.Fatalf("host image scores: %v %v", host, err)
	}

	// A new advisory for zlib: the re-match reaches the images through the
	// reverse index and opens a finding on the host running it.
	f.upsert(f.perCVE(cve2, row("zlib", "standard", nil, "medium")))
	dr, err := f.s.DrainAdvisoryChanges(ctx, DrainOptions{Distro: f.distro})
	if err != nil || len(dr.Changed) != 1 {
		t.Fatalf("drain: %+v %v", dr, err)
	}
	hosts, err := f.s.HostsWithImageSoftware(ctx, dr.Changed)
	if err != nil || !slices.Contains(hosts, f.hostID) || !slices.Contains(hosts, f.hostV) {
		t.Fatalf("hosts with image software: %v %v", hosts, err)
	}
	lists, err := f.s.ImageSBOMsContaining(ctx, dr.Changed)
	if err != nil || len(lists) != 2 {
		t.Fatalf("lists containing: %v %v", lists, err)
	}
	for _, l := range lists {
		f.score(l.SBOMID)
	}
	if res = f.reconcileHost(f.hostID); res.Opened != 1 || res.Kept != 1 {
		t.Errorf("after new advisory: %+v", res)
	}
	if sc = f.scoreOf(f.userU, unused); *sc.Vulns != 2 || *sc.Medium != 1 {
		t.Errorf("re-scored: %+v", sc)
	}

	// KEV listing: findings_rerank re-ranks image findings too, and the
	// lists matched to the CVE are re-scored.
	since := time.Now().Add(-time.Minute)
	if _, err := f.s.Pool.Exec(ctx, `
		INSERT INTO cves (id, is_kev, cvss_v3_score) VALUES ($1, true, 9.1)
		ON CONFLICT (id) DO UPDATE SET is_kev = true, cvss_v3_score = 9.1, updated_at = now()`, cve1); err != nil {
		t.Fatal(err)
	}
	if rr, err := f.s.RerankFindings(ctx, since); err != nil || rr.Updated < 1 {
		t.Fatalf("rerank: %+v %v", rr, err)
	}
	if g := f.imageFindings(f.hostID)[key1]; g.Severity != "critical" || g.Status != "open" {
		t.Errorf("image finding after rerank: %+v", g)
	}
	rescore, err := f.s.ImageSBOMsWithCVEsChangedSince(ctx, since)
	if err != nil || !slices.Contains(rescore, unusedList.SBOMID) {
		t.Fatalf("lists to re-score: %v %v", rescore, err)
	}
	f.score(unusedList.SBOMID)
	if sc = f.scoreOf(f.userU, unused); *sc.WorstSeverity != "critical" || !*sc.KEV || *sc.MaxCVSS != 9.1 {
		t.Errorf("score after KEV: %+v", sc)
	}

	// The container goes away: its image's findings resolve (the image is
	// still present, unused). A new container reopens them.
	f.removeContainer(f.hostID, web, 5)
	if res = f.reconcileHost(f.hostID); res.Resolved != 2 || res.Images != 0 {
		t.Errorf("container removed: %+v", res)
	}
	if g := f.imageFindings(f.hostID)[key1]; g.Status != "resolved" {
		t.Errorf("after removal: %+v", g)
	}
	f.container(f.hostID, used, "web", "running", 6)
	if res = f.reconcileHost(f.hostID); res.Reopened != 2 {
		t.Errorf("container back: %+v", res)
	}
	if g := f.imageFindings(f.hostID)[key1]; g.Status != "open" || g.ReopenCount != 1 {
		t.Errorf("reopened: %+v", g)
	}
}

// An agent's list is scoped to its user: user U's list for a local image
// raises findings on U's host only; user V, running the same image id,
// sees no list at all.
func TestImageFindingsAgentListScope(t *testing.T) {
	f := newImageFixture(t)
	ctx := context.Background()
	cve := f.cve()
	f.upsert(f.perCVE(cve, row("openssl", "standard", sp("3.0.2-2"), "high")))

	local := f.image("local")
	f.onHost(f.hostID, local, "myapp:dev")
	f.onHost(f.hostV, local, "myapp:dev")
	f.container(f.hostID, local, "app", "running", 1)
	f.container(f.hostV, local, "app", "running", 1)
	if ok, err := f.s.RecordImageSBOMFailure(ctx, ImageSBOMFailure{Key: local, Status: SBOMStatusUnavailable,
		Reason: "private or local image, waiting for the agent"}); err != nil || !ok {
		t.Fatalf("server failure: %v %v", ok, err)
	}
	f.list(local, f.userU, SBOMSourceAgentSyft, f.deb("openssl", "openssl", "3.0.2-1"))

	if res := f.reconcileHost(f.hostID); res.Opened != 1 {
		t.Errorf("user U: %+v", res)
	}
	if res := f.reconcileHost(f.hostV); res.Opened != 0 || res.Images != 0 {
		t.Errorf("user V must not use U's agent list: %+v", res)
	}
	if su := f.scoreOf(f.userU, local); su.ListStatus != SBOMStatusOK || *su.ListSource != SBOMSourceAgentSyft || *su.Vulns != 1 {
		t.Errorf("U's score: %+v", su)
	}
	sv := f.scoreOf(f.userV, local)
	if sv.ListStatus != SBOMStatusUnavailable || sv.ListReason == nil || sv.Vulns != nil || sv.Clean() {
		t.Errorf("V's score: %+v", sv)
	}
	fleet, err := f.s.FleetImageScores(ctx, f.userV)
	if err != nil || len(fleet) != 1 || fleet[0].Key != local {
		t.Errorf("V's fleet: %+v %v", fleet, err)
	}

	// An image nobody attempted: "none", distinguishable from clean.
	fresh := f.image("fresh")
	if s := f.scoreOf(f.userU, fresh); s.ListStatus != SBOMStatusNone || s.Scored {
		t.Errorf("no list yet: %+v", s)
	}
}

// Reconcile waits while an image list in scope has versions the matcher
// hasn't evaluated, and scoring writes nothing until then.
func TestImageFindingsWaitForMatcher(t *testing.T) {
	f := newImageFixture(t)
	ctx := context.Background()
	k := f.image("pending")
	f.onHost(f.hostID, k, "x:1")
	f.container(f.hostID, k, "x", "created", 1)
	res, err := f.s.WriteImageSBOM(ctx, ImageSBOMInput{Key: k, Source: SBOMSourceAttestation,
		Release: "jammy", Packages: []ImagePackage{f.deb("libfoo", "foo", "1.0-1")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.ReconcileHostFindings(ctx, f.hostID); err != ErrUnevaluated {
		t.Errorf("reconcile before matching: %v, want ErrUnevaluated", err)
	}
	if r, err := f.s.ScoreImageSBOM(ctx, res.SBOMID); err != nil || r.Pending != 1 {
		t.Errorf("score before matching: %+v %v", r, err)
	}
	if s := f.scoreOf(f.userU, k); s.Scored {
		t.Errorf("scored before matching: %+v", s)
	}
	if _, err := f.s.MatchVersions(ctx, res.RematchSoftwareIDs()); err != nil {
		t.Fatal(err)
	}
	f.score(res.SBOMID)
	if s := f.scoreOf(f.userU, k); !s.Scored || *s.Vulns != 0 {
		t.Errorf("after matching: %+v", s)
	}
	f.reconcileHost(f.hostID)
	stale, err := f.s.StaleImageScores(ctx, 1000)
	if err != nil || slices.Contains(stale, res.SBOMID) {
		t.Errorf("fresh score reported stale: %v %v", stale, err)
	}
}
