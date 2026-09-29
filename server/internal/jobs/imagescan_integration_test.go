package jobs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/feeds"
	"github.com/pippinmole/upkeep.sh/server/internal/imagesbom"
	"github.com/pippinmole/upkeep.sh/server/internal/imagescan"
	"github.com/pippinmole/upkeep.sh/server/internal/registry"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

// The test binary doubles as the scan's catalog child.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == imagescan.CatalogCommand {
		if err := imagescan.RunChild(os.Args[2:]); err != nil {
			os.Stderr.WriteString(err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func gzipLayer(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, name := range []string{"etc/os-release", "lib/apk/db/installed"} {
		body, ok := files[name]
		if !ok {
			continue
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(body))
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// pushScannable pushes a linux/amd64 Alpine-like image without an SBOM
// attestation. Returns the image id (index digest) and repo digest.
func (r *testRegistry) pushScannable(t *testing.T, tag string) (string, string) {
	layer, layerSize := r.put(t, gzipLayer(t, map[string]string{
		"etc/os-release": "ID=alpine\nVERSION_ID=3.24.1\n",
		"lib/apk/db/installed": "P:musl\nV:1.2.5-r10\nA:x86_64\no:musl\n\n" +
			"P:busybox-binsh\nV:1.37.0-r18\nA:x86_64\no:busybox\n\n",
	}))
	cfg, cfgSize := r.put(t, []byte(`{"architecture":"amd64","os":"linux"}`))
	man, manSize := r.put(t, map[string]any{"schemaVersion": 2, "mediaType": registry.MediaTypeOCIManifest,
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg, "size": cfgSize},
		"layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layer, "size": layerSize}}})
	idx, _ := r.put(t, map[string]any{"schemaVersion": 2, "mediaType": registry.MediaTypeOCIIndex,
		"manifests": []any{map[string]any{"mediaType": registry.MediaTypeOCIManifest, "digest": man, "size": manSize,
			"platform": map[string]string{"os": "linux", "architecture": "amd64"}}},
		"annotations": map[string]string{"test": tag}})
	return idx, strings.TrimPrefix(r.srv.URL, "https://") + "/library/alpine@" + idx
}

func scanConfig(t *testing.T, reg *testRegistry, scan imagescan.Config) ImagesConfig {
	scan.Dir = t.TempDir()
	scan.Command = []string{os.Args[0], imagescan.CatalogCommand}
	return ImagesConfig{FetchEnabled: true, DisableSchedule: true, Registry: registry.Config{Guard: reg.guard()},
		Scan: true, Scanner: scan}
}

// End to end: no attestation, so image_sbom hands over to image_scan,
// which pulls the image, runs Syft and stores a fleet-wide server-syft list.
func TestImageScanJobEndToEnd(t *testing.T) {
	f := newImageFixture(t)
	reg := newTestRegistry(t)
	imageID, repoDigest := reg.pushScannable(t, f.tag)
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = f.s.Pool.Exec(context.Background(), `DELETE FROM river_job WHERE kind = 'image_scan' AND args->>'image_id' = $1`, imageID)
	})
	f.pushHost(imageID, repoDigest)

	icfg := scanConfig(t, reg, imagescan.Config{})
	client, err := NewClient(f.s.Pool, f.s, &feeds.Syncer{Store: f.s, Cfg: feeds.DefaultConfig()}, Config{
		DisableMatcherSchedule: true, DisableAlertSchedule: true, DisableMaintenanceSchedule: true, Images: icfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = client.Stop(stopCtx)
	})

	key := store.ImageKey{ImageID: imageID, OS: "linux", Arch: "amd64"}
	var ref *store.ImageSBOMRef
	for deadline := time.Now().Add(60 * time.Second); ref == nil; {
		if time.Now().After(deadline) {
			st, _ := f.s.ServerImageSBOMState(ctx, key)
			t.Fatalf("no ok list; state %+v", st)
		}
		time.Sleep(200 * time.Millisecond)
		if ref, err = f.s.EffectiveImageSBOM(ctx, "", key); err != nil {
			t.Fatal(err)
		}
	}
	if ref.Source != store.SBOMSourceServerSyft || ref.OwnerUserID != "" {
		t.Errorf("list = %+v", ref)
	}
	var tool, toolVersion, distro, release string
	var count, attempts int
	if err := f.s.Pool.QueryRow(ctx, `SELECT tool_name, tool_version, distro, release, package_count, attempts
		FROM image_sbom_state WHERE id = $1`, ref.SBOMID).Scan(&tool, &toolVersion, &distro, &release, &count, &attempts); err != nil {
		t.Fatal(err)
	}
	if tool != "syft" || !strings.HasPrefix(toolVersion, "v1.") || distro != "alpine" || release != "3.24" || count != 2 || attempts != 0 {
		t.Errorf("state = %s %s %s %s %d packages, %d attempts", tool, toolVersion, distro, release, count, attempts)
	}
	rows, err := f.s.ImageSoftware(ctx, ref.SBOMID)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		var src string
		_ = f.s.Pool.QueryRow(ctx, `SELECT source_name FROM software_versions WHERE id = $1`, r.SoftwareID).Scan(&src)
		if r.Ecosystem != "apk" || r.Distro != "alpine" || r.Release != "3.24" ||
			(r.Name == "busybox-binsh" && src != "busybox") {
			t.Errorf("row = %+v, source %q", r, src)
		}
	}
	if left, _ := os.ReadDir(icfg.Scanner.Dir); len(left) != 0 {
		t.Errorf("%d entries left in the scan dir", len(left))
	}
}

// Hand-over bookkeeping, scan failures, and what never gets overwritten.
func TestImageScanFailures(t *testing.T) {
	f := newImageFixture(t)
	reg := newTestRegistry(t)
	ctx := context.Background()
	state := func(id string) *store.ImageSBOMState {
		st, err := f.s.ServerImageSBOMState(ctx, store.ImageKey{ImageID: id, OS: "linux", Arch: "amd64"})
		if err != nil || st == nil {
			t.Fatalf("state %v %v", st, err)
		}
		return st
	}
	fetcher := func(scan imagescan.Config) *imagesbom.Fetcher {
		return &imagesbom.Fetcher{Store: f.s, Cfg: ImagesFetcherConfig(scanConfig(t, reg, scan))}
	}

	imageID, d := reg.pushScannable(t, f.tag+"-big")
	f.pushHost(imageID, d)
	key := store.ImageKey{ImageID: imageID, OS: "linux", Arch: "amd64"}

	// No attestation with scanning on: a hand-over, not a failed attempt.
	out, err := fetcher(imagescan.Config{}).Run(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if st := state(imageID); !out.Scan || st.Reason != store.SBOMReasonNoAttestation || st.Attempts != 0 || st.NextAttemptAt != nil {
		t.Errorf("hand-over: scan %v, %+v", out.Scan, st)
	}
	keys, err := f.s.ImageScanSweep(ctx, 100000)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, k := range keys {
		found = found || k == key
	}
	if !found {
		t.Error("scan sweep misses the handed-over key")
	}

	// Over the size cap: unavailable with the scan's reason, counted.
	small := imagescan.Config{MaxCompressedBytes: 10}
	if _, err := fetcher(small).Scan(ctx, key); err != nil {
		t.Fatal(err)
	}
	if st := state(imageID); st.Status != store.SBOMStatusUnavailable || !strings.Contains(st.Reason, "scan size limit") ||
		st.Attempts != 1 || st.NextAttemptAt != nil {
		t.Errorf("too large: %+v", st)
	}

	// Fetching disabled: the scan contacts nothing.
	off := &imagesbom.Fetcher{Store: f.s, Cfg: imagesbom.Config{Enabled: false}}
	if _, err := off.Scan(ctx, key); err != nil {
		t.Fatal(err)
	}
	if st := state(imageID); st.Reason != store.SBOMReasonFetchDisabled {
		t.Errorf("disabled: %+v", st)
	}

	// A good scan, then a failing one: the list stays.
	if out, err := fetcher(imagescan.Config{}).Scan(ctx, key); err != nil || out.Status != store.SBOMStatusOK {
		t.Fatalf("scan: %+v %v", out, err)
	}
	if out, err := fetcher(small).Scan(ctx, key); err != nil || out.Status != imagesbom.StatusSkipped {
		t.Errorf("rescan of an ok list: %+v %v", out, err)
	}
	if st := state(imageID); st.Status != store.SBOMStatusOK {
		t.Errorf("ok list overwritten: %+v", st)
	}

	// An attestation list is never rescanned.
	att, d := reg.pushImage(t, f.tag+"-att", true)
	f.pushHost(att, d)
	attKey := store.ImageKey{ImageID: att, OS: "linux", Arch: "amd64"}
	if out, err := fetcher(imagescan.Config{}).Run(ctx, attKey); err != nil || out.Status != store.SBOMStatusOK || out.Scan {
		t.Fatalf("attestation: %+v %v", out, err)
	}
	if out, err := fetcher(imagescan.Config{}).Scan(ctx, attKey); err != nil || out.Status != imagesbom.StatusSkipped {
		t.Errorf("scan of an attestation list: %+v %v", out, err)
	}
}
