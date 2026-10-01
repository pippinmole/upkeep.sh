package store

// Image scores of end-of-life base images (migration 0020, matcher.Version
// 3) against a real database: skipped unless SW_TEST_DATABASE_URL is set.
// A release out of support, or one distro_releases doesn't know, matches
// no advisories (only supported releases are imported), so its packages
// are "not assessed" and the image is never clean.

import (
	"context"
	"testing"

	"github.com/pippinmole/upkeep.sh/server/internal/inventory"
	"github.com/pippinmole/upkeep.sh/server/internal/matcher"
	"github.com/pippinmole/upkeep.sh/server/internal/purl"
)

func TestImageScoreEndOfLifeRelease(t *testing.T) {
	f := newImageFixture(t)
	ctx := context.Background()

	// Releases of a real assessed distro, unique to this run.
	supported, eol, unknown := f.distro+"-sup", f.distro+"-eol", f.distro+"-unk"
	if _, err := f.s.Pool.Exec(ctx, `
		INSERT INTO distro_releases (distro, codename, version, osv_ecosystem, eol_date, supported) VALUES
			('debian', $1, $1, $1, NULL, true), ('debian', $2, $2, $2, '2024-06-30', false)
	`, supported, eol); err != nil {
		t.Fatal(err)
	}
	var images []string
	t.Cleanup(func() {
		_, _ = f.s.Pool.Exec(ctx, `DELETE FROM image_sbom_state WHERE image_id = ANY($1)`, images)
		_, _ = f.s.Pool.Exec(ctx, `DELETE FROM software_versions WHERE distro = 'debian' AND release = ANY($1)`,
			[]string{supported, eol, unknown})
		_, _ = f.s.Pool.Exec(ctx, `DELETE FROM distro_releases WHERE distro = 'debian' AND codename = ANY($1)`,
			[]string{supported, eol})
	})

	write := func(name, release string) ImageScore {
		t.Helper()
		k := f.image(name)
		images = append(images, k.ImageID)
		f.onHost(f.hostID, k, name+":1")
		var pkgs []ImagePackage
		for _, n := range []string{"libc6", "zlib1g", "bash"} {
			pkgs = append(pkgs, ImagePackage{Package: purl.Package{
				Ecosystem: "deb", Distro: "debian", Release: release,
				KnownType: true, Item: inventory.Item{Name: n + "-" + f.distro, Version: "1.0-1", Arch: "amd64"},
			}})
		}
		// One language package: never assessed yet, whatever the release.
		pkgs = append(pkgs, ImagePackage{Package: purl.Package{
			Ecosystem: "gem", KnownType: true,
			Item: inventory.Item{Name: "rack-" + f.distro, Version: "2.2.8"},
		}})
		res, err := f.s.WriteImageSBOM(ctx, ImageSBOMInput{
			Key: k, Source: SBOMSourceAttestation,
			OS: purl.OSRelease{ID: "debian", VersionCodename: release}, Release: release, Packages: pkgs,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.MatchVersions(ctx, res.RematchSoftwareIDs()); err != nil {
			t.Fatal(err)
		}
		f.score(res.SBOMID)
		return f.scoreOf(f.userU, k)
	}

	sup := write("sup", supported)
	if *sup.Packages != 4 || *sup.NotAssessed != 1 || *sup.Vulns != 0 || sup.Clean() ||
		sup.ReleaseStatus() != matcher.ReleaseSupported {
		t.Errorf("supported release: %+v status %q", sup, sup.ReleaseStatus())
	}

	old := write("eol", eol)
	if *old.Packages != 4 || *old.NotAssessed != 4 || *old.Vulns != 0 || old.Clean() ||
		old.ReleaseStatus() != matcher.ReleaseOutOfSupport || old.ReleaseEOL == nil ||
		old.ReleaseEOL.UTC().Format("2006-01-02") != "2024-06-30" {
		t.Errorf("out-of-support release: %+v status %q", old, old.ReleaseStatus())
	}

	unk := write("unk", unknown)
	if *unk.NotAssessed != 4 || unk.Clean() || unk.ReleaseStatus() != matcher.ReleaseUnknown {
		t.Errorf("unknown release: %+v status %q", unk, unk.ReleaseStatus())
	}
}
