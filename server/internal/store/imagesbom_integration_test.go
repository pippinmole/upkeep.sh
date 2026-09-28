package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/purl"
)

// Image package lists (migration 0014) against a real database. Each test
// uses its own users, image ids and a unique distro / npm scope, and
// deletes all of it afterwards.

type sbomFixture struct {
	t            *testing.T
	s            *Store
	tag          string
	userA, userB string
	osr          purl.OSRelease
}

func newSBOMFixture(t *testing.T) *sbomFixture {
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
	tag := "swtest-" + hex.EncodeToString(b)
	f := &sbomFixture{t: t, s: s, tag: tag, osr: purl.OSRelease{ID: tag, VersionID: "12"}}
	for suffix, u := range map[string]*string{"a": &f.userA, "b": &f.userB} {
		if err := s.Pool.QueryRow(ctx, `INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id`,
			tag+"-"+suffix+"@test.invalid").Scan(u); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = s.Pool.Exec(ctx, `DELETE FROM image_sbom_state WHERE image_id LIKE $1`, "sha256:"+tag+"%")
		_, _ = s.Pool.Exec(ctx, `DELETE FROM container_images WHERE image_id LIKE $1`, "sha256:"+tag+"%")
		_, _ = s.Pool.Exec(ctx, `DELETE FROM users WHERE id = ANY($1::uuid[])`, []string{f.userA, f.userB})
		_, _ = s.Pool.Exec(ctx, `DELETE FROM river_job WHERE kind = 'match_versions' AND args->'ids' @> (
			SELECT to_jsonb(array_agg(id)) FROM software_versions WHERE distro = $1)`, tag)
		_, _ = s.Pool.Exec(ctx, `DELETE FROM software_versions WHERE distro = $1 OR name LIKE $2`, tag, "@"+tag+"/%")
		s.Close()
	})
	return f
}

// image interns a container_images row and returns its key.
func (f *sbomFixture) image(n string) ImageKey {
	f.t.Helper()
	k := ImageKey{ImageID: "sha256:" + f.tag + "-" + n, OS: "linux", Arch: "amd64"}
	if _, err := f.s.Pool.Exec(context.Background(),
		`INSERT INTO container_images (image_id, os, arch, variant) VALUES ($1, $2, $3, $4)`,
		k.ImageID, k.OS, k.Arch, k.Variant); err != nil {
		f.t.Fatal(err)
	}
	return k
}

// pkg maps a purl template; "{tag}" is replaced by the fixture's tag so
// language packages are unique too.
func (f *sbomFixture) pkg(p string, paths ...string) ImagePackage {
	f.t.Helper()
	m, err := purl.MapString(p, f.osr, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return ImagePackage{Package: m, Paths: paths}
}

func (f *sbomFixture) npm(name, version string, paths ...string) ImagePackage {
	return f.pkg("pkg:npm/%40"+f.tag+"/"+name+"@"+version, paths...)
}

func (f *sbomFixture) write(key ImageKey, owner, source string, pkgs ...ImagePackage) ImageSBOMResult {
	f.t.Helper()
	res, err := f.s.WriteImageSBOM(context.Background(), ImageSBOMInput{
		Key: key, OwnerUserID: owner, Source: source, ToolName: "syft", ToolVersion: "1.20.0",
		GeneratedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), OS: f.osr, Release: "12", Packages: pkgs,
	})
	if err != nil {
		f.t.Fatalf("write %s/%s: %v", source, owner, err)
	}
	return res
}

func (f *sbomFixture) names(sbomID int64) []string {
	f.t.Helper()
	rows, err := f.s.ImageSoftware(context.Background(), sbomID)
	if err != nil {
		f.t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.Name+"@"+r.Version)
	}
	return out
}

func (f *sbomFixture) effective(user string, key ImageKey) *ImageSBOMRef {
	f.t.Helper()
	r, err := f.s.EffectiveImageSBOM(context.Background(), user, key)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func TestImageSBOMWriteIsIdempotent(t *testing.T) {
	f := newSBOMFixture(t)
	ctx := context.Background()
	key := f.image("a")

	deb := f.pkg("pkg:deb/" + f.tag + "/libssl3@3.0.15-1~deb12u1?arch=amd64&upstream=openssl")
	login := f.pkg("pkg:deb/" + f.tag + "/login@1%3A4.13%2Bdfsg1-1?arch=amd64&upstream=shadow")
	// Same npm package at two paths (and a repeated path): one row, merged.
	core1 := f.npm("core", "7.24.0", "/app/node_modules/@x/core/package.json")
	core2 := f.npm("core", "7.24.0", "/srv/node_modules/@x/core/package.json", "/app/node_modules/@x/core/package.json")

	res := f.write(key, "", SBOMSourceAttestation, deb, login, core1, core2)
	if res.Packages != 3 || len(res.Added) != 3 || len(res.Removed) != 0 || len(res.NewSoftwareIDs) != 3 {
		t.Fatalf("first write: %+v", res)
	}
	rows, err := f.s.ImageSoftware(ctx, res.SBOMID)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		switch r.Name {
		case "@" + f.tag + "/core":
			want := []string{"/app/node_modules/@x/core/package.json", "/srv/node_modules/@x/core/package.json"}
			if !slices.Equal(r.Paths, want) || r.Ecosystem != "npm" || r.Distro != "" {
				t.Errorf("npm row: %+v", r)
			}
		case "login":
			if r.Version != "1:4.13+dfsg1-1" || r.Distro != f.tag || r.Release != "12" {
				t.Errorf("login row: %+v", r)
			}
		}
	}
	var src string
	_ = f.s.Pool.QueryRow(ctx, `SELECT source_name FROM software_versions WHERE distro = $1 AND name = 'libssl3'`, f.tag).Scan(&src)
	if src != "openssl" {
		t.Errorf("libssl3 source = %q, want openssl", src)
	}

	// Same list again: nothing new, same list id.
	again := f.write(key, "", SBOMSourceAttestation, core2, login, deb, core1)
	if again.SBOMID != res.SBOMID || len(again.Added)+len(again.Removed)+len(again.NewSoftwareIDs) != 0 {
		t.Fatalf("rewrite: %+v", again)
	}

	// A re-generated list replaces the set atomically.
	deb2 := f.pkg("pkg:deb/" + f.tag + "/libssl3@3.0.16-1~deb12u1?arch=amd64&upstream=openssl")
	upd := f.write(key, "", SBOMSourceServerSyft, deb2, login, core1)
	if len(upd.Added) != 1 || len(upd.Removed) != 1 || len(upd.NewSoftwareIDs) != 1 || upd.Packages != 3 {
		t.Fatalf("replace: %+v", upd)
	}
	want := []string{"libssl3@3.0.16-1~deb12u1", "login@1:4.13+dfsg1-1", "@" + f.tag + "/core@7.24.0"}
	slices.Sort(want)
	got := f.names(res.SBOMID)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("after replace: %v, want %v", got, want)
	}
	var (
		source string
		count  int
	)
	_ = f.s.Pool.QueryRow(ctx, `SELECT source, package_count FROM image_sbom_state WHERE id = $1`, res.SBOMID).Scan(&source, &count)
	if source != SBOMSourceServerSyft || count != 3 {
		t.Errorf("state: source %s count %d", source, count)
	}
}

func TestImageSBOMOwnerScoping(t *testing.T) {
	f := newSBOMFixture(t)
	ctx := context.Background()
	key := f.image("local")
	shared := f.pkg("pkg:deb/" + f.tag + "/bash@5.2.15-2?arch=amd64")

	// The server can't get it: private or local.
	ok, err := f.s.RecordImageSBOMFailure(ctx, ImageSBOMFailure{Key: key, Status: SBOMStatusUnavailable,
		Reason: "private or local image, waiting for the agent"})
	if err != nil || !ok {
		t.Fatalf("record failure: %v %v", ok, err)
	}
	if f.effective(f.userA, key) != nil || f.effective("", key) != nil {
		t.Fatal("no list yet, want nil")
	}

	// User A's agent sends a list: only A sees it.
	agentA := f.write(key, f.userA, SBOMSourceAgentSyft, shared, f.npm("a-only", "1.0.0"))
	if e := f.effective(f.userA, key); e == nil || e.SBOMID != agentA.SBOMID || e.OwnerUserID != f.userA {
		t.Fatalf("A effective = %+v", e)
	}
	if e := f.effective(f.userB, key); e != nil {
		t.Fatalf("B sees A's agent list: %+v", e)
	}
	// B's agent sends a different (possibly poisoned) list: A unaffected.
	agentB := f.write(key, f.userB, SBOMSourceAgentSyft, shared)
	if e := f.effective(f.userA, key); e.SBOMID != agentA.SBOMID {
		t.Fatalf("A effective after B's write = %+v", e)
	}
	if e := f.effective(f.userB, key); e == nil || e.SBOMID != agentB.SBOMID {
		t.Fatalf("B effective = %+v", e)
	}

	// Server list becomes ok: it wins for everyone.
	server := f.write(key, "", SBOMSourceServerSyft, shared)
	for _, u := range []string{f.userA, f.userB, ""} {
		if e := f.effective(u, key); e == nil || e.SBOMID != server.SBOMID || e.OwnerUserID != "" {
			t.Fatalf("user %q effective = %+v, want server list %d", u, e, server.SBOMID)
		}
	}
	// A failure never overwrites an ok list.
	ok, err = f.s.RecordImageSBOMFailure(ctx, ImageSBOMFailure{Key: key, Status: SBOMStatusError, Reason: "boom"})
	if err != nil || ok {
		t.Fatalf("failure over ok list: %v %v", ok, err)
	}
	var status string
	var attempts int
	_ = f.s.Pool.QueryRow(ctx, `SELECT status, attempts FROM image_sbom_state WHERE id = $1`, server.SBOMID).Scan(&status, &attempts)
	if status != SBOMStatusOK || attempts != 0 {
		t.Errorf("server state after failure: %s, attempts %d", status, attempts)
	}

	// Reverse lookup: the shared version is in all three lists.
	var bashID int64
	_ = f.s.Pool.QueryRow(ctx, `SELECT id FROM software_versions WHERE distro = $1 AND name = 'bash'`, f.tag).Scan(&bashID)
	refs, err := f.s.ImageSBOMsContaining(ctx, []int64{bashID})
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for _, r := range refs {
		ids = append(ids, r.SBOMID)
		if r.Key != key {
			t.Errorf("ref key %+v", r.Key)
		}
	}
	want := []int64{agentA.SBOMID, agentB.SBOMID, server.SBOMID}
	slices.Sort(want)
	if !slices.Equal(ids, want) {
		t.Errorf("containing bash = %v, want %v", ids, want)
	}

	// Deleting a user drops its agent list, not the others.
	if _, err := f.s.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, f.userB); err != nil {
		t.Fatal(err)
	}
	if refs, _ := f.s.ImageSBOMsContaining(ctx, []int64{bashID}); len(refs) != 2 {
		t.Errorf("after deleting B: %d lists", len(refs))
	}
}

func TestImageSBOMFailureBookkeeping(t *testing.T) {
	f := newSBOMFixture(t)
	ctx := context.Background()
	key := f.image("flaky")
	next := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	for range 2 {
		if ok, err := f.s.RecordImageSBOMFailure(ctx, ImageSBOMFailure{Key: key, Status: SBOMStatusError,
			Reason: "registry returned 429", NextAttemptAt: &next}); err != nil || !ok {
			t.Fatalf("record: %v %v", ok, err)
		}
	}
	var attempts int
	var got time.Time
	_ = f.s.Pool.QueryRow(ctx, `SELECT attempts, next_attempt_at FROM image_sbom_state WHERE image_id = $1`,
		key.ImageID).Scan(&attempts, &got)
	if attempts != 2 || !got.Equal(next) {
		t.Errorf("attempts %d next %v", attempts, got)
	}
	res := f.write(key, "", SBOMSourceAttestation, f.npm("x", "1.0.0"))
	_ = f.s.Pool.QueryRow(ctx, `SELECT attempts FROM image_sbom_state WHERE id = $1`, res.SBOMID).Scan(&attempts)
	if attempts != 0 {
		t.Errorf("attempts after ok = %d", attempts)
	}
}

func TestImageSBOMValidation(t *testing.T) {
	f := newSBOMFixture(t)
	key := f.image("v")
	for _, in := range []ImageSBOMInput{
		{Key: key, Source: SBOMSourceAgentSyft},                         // agent list without owner
		{Key: key, Source: SBOMSourceAttestation, OwnerUserID: f.userA}, // server list with owner
		{Key: key, Source: "scout"},
	} {
		if _, err := f.s.WriteImageSBOM(context.Background(), in); err == nil {
			t.Errorf("WriteImageSBOM(%+v) succeeded", in)
		}
	}
}

// An image's real upstream source upgrades a host's inferred one (same
// interned row), resetting its matcher bookkeeping.
func TestImageSBOMUpgradesInferredSource(t *testing.T) {
	f := newSBOMFixture(t)
	ctx := context.Background()
	if _, err := f.s.Pool.Exec(ctx, `
		INSERT INTO software_versions (ecosystem, distro, release, name, version, arch, source_name, source_version, source_inferred, matcher_version)
		VALUES ('deb', $1, '12', 'libssl3', '3.0.15-1', 'amd64', 'libssl3', '3.0.15-1', true, 1)`, f.tag); err != nil {
		t.Fatal(err)
	}
	res := f.write(f.image("up"), "", SBOMSourceAttestation,
		f.pkg("pkg:deb/"+f.tag+"/libssl3@3.0.15-1?arch=amd64&upstream=openssl"))
	if len(res.ResetSoftwareIDs) != 1 || len(res.NewSoftwareIDs) != 0 || len(res.RematchSoftwareIDs()) != 1 {
		t.Fatalf("result: %+v", res)
	}
}

func TestDistroReleaseIndex(t *testing.T) {
	f := newSBOMFixture(t)
	ix, err := f.s.DistroReleaseIndex(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := ix.Codename("debian", "12"); c != "bookworm" {
		t.Errorf("debian 12 = %q", c)
	}
	if c, _ := ix.Codename("ubuntu", "22.04"); c != "jammy" {
		t.Errorf("ubuntu 22.04 = %q", c)
	}
}
