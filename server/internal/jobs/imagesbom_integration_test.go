package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/purl"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

// An image package list enqueues match_versions for the versions it
// interned in its own transaction, like ingest: no list, no job.
func TestEnqueueAfterImageSBOMIsTransactional(t *testing.T) {
	dsn := os.Getenv("SW_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SW_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	tag := "swtest-" + hex.EncodeToString(b)
	key := store.ImageKey{ImageID: "sha256:" + tag, OS: "linux", Arch: "amd64"}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO container_images (image_id, os, arch, variant) VALUES ($1, $2, $3, '')`,
		key.ImageID, key.OS, key.Arch); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = s.Pool.Exec(ctx, `DELETE FROM river_job WHERE kind = 'match_versions' AND args->'ids' @> (
			SELECT to_jsonb(array_agg(id)) FROM software_versions WHERE distro = $1)`, tag)
		_, _ = s.Pool.Exec(ctx, `DELETE FROM river_job WHERE kind = 'reconcile_image' AND args->>'image_id' = $1`, key.ImageID)
		_, _ = s.Pool.Exec(ctx, `DELETE FROM image_sbom_state WHERE image_id = $1`, key.ImageID)
		_, _ = s.Pool.Exec(ctx, `DELETE FROM container_images WHERE image_id = $1`, key.ImageID)
		_, _ = s.Pool.Exec(ctx, `DELETE FROM software_versions WHERE distro = $1`, tag)
	})
	client, err := NewInserter(s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	osr := purl.OSRelease{ID: tag, VersionID: "12"}
	var pkgs []store.ImagePackage
	for _, p := range []string{"pkg:deb/x/a@1?arch=amd64", "pkg:deb/x/b@1?arch=amd64&upstream=bsrc"} {
		m, err := purl.MapString(p, osr, nil)
		if err != nil {
			t.Fatal(err)
		}
		pkgs = append(pkgs, store.ImagePackage{Package: m})
	}
	jobs := func() int {
		var n int
		_ = s.Pool.QueryRow(ctx, `
			SELECT count(*) FROM river_job
			WHERE kind = 'match_versions' AND jsonb_array_length(args->'ids') = 2
			  AND args->'ids' @> (SELECT to_jsonb(array_agg(id)) FROM software_versions WHERE distro = $1)`, tag).Scan(&n)
		return n
	}
	write := func(fail bool) error {
		_, err := s.WriteImageSBOM(ctx, store.ImageSBOMInput{
			Key: key, Source: store.SBOMSourceAttestation, OS: osr, Release: "12", Packages: pkgs,
			AfterWrite: func(ctx context.Context, tx pgx.Tx, res store.ImageSBOMResult) error {
				if err := EnqueueAfterImageSBOM(ctx, client, tx, res); err != nil {
					return err
				}
				if fail {
					return errors.New("injected")
				}
				return nil
			},
		})
		return err
	}
	if err := write(true); err == nil {
		t.Fatal("injected failure not returned")
	}
	var lists int
	_ = s.Pool.QueryRow(ctx, `SELECT count(*) FROM image_sbom_state WHERE image_id = $1`, key.ImageID).Scan(&lists)
	if n := jobs(); n != 0 || lists != 0 {
		t.Fatalf("after rollback: %d jobs, %d lists", n, lists)
	}
	if err := write(false); err != nil {
		t.Fatal(err)
	}
	if n := jobs(); n != 1 {
		t.Fatalf("after commit: %d match_versions jobs, want 1", n)
	}
	// Rewriting interns nothing new: no further job.
	if err := write(false); err != nil {
		t.Fatal(err)
	}
	var total int
	_ = s.Pool.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = 'match_versions' AND args->'ids' @> (
		SELECT to_jsonb(min(id)) FROM software_versions WHERE distro = $1)`, tag).Scan(&total)
	if total != 1 {
		t.Fatalf("after rewrite: %d jobs, want 1", total)
	}
	// Every committed write queues reconcile_image for its key (score the
	// list, then reconcile the hosts having the image); the rolled-back
	// one didn't.
	var reconciles int
	_ = s.Pool.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = 'reconcile_image' AND args->>'image_id' = $1`,
		key.ImageID).Scan(&reconciles)
	if reconciles != 2 {
		t.Fatalf("reconcile_image jobs: %d, want 2", reconciles)
	}
}
