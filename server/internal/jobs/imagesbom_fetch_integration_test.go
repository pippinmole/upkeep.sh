package jobs

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/feeds"
	"github.com/pippinmole/upkeep.sh/server/internal/hostfacts"
	"github.com/pippinmole/upkeep.sh/server/internal/imagesbom"
	"github.com/pippinmole/upkeep.sh/server/internal/netguard"
	"github.com/pippinmole/upkeep.sh/server/internal/registry"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

// testRegistry is a minimal anonymous OCI registry over TLS: manifests
// and blobs by digest, no referrers API, optional forced status.
type testRegistry struct {
	srv  *httptest.Server
	mu   sync.Mutex
	objs map[string][]byte
	down bool // answer 503
}

func newTestRegistry(t *testing.T) *testRegistry {
	r := &testRegistry{objs: map[string][]byte{}}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.down {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		i := strings.LastIndexByte(req.URL.Path, '/')
		b, ok := r.objs[req.URL.Path[i+1:]]
		if !ok || strings.Contains(req.URL.Path, "/referrers/") {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *testRegistry) put(t *testing.T, v any) (digest string, size int) {
	b, ok := v.([]byte)
	if !ok {
		var err error
		if b, err = json.Marshal(v); err != nil {
			t.Fatal(err)
		}
	}
	s := sha256.Sum256(b)
	digest = "sha256:" + hex.EncodeToString(s[:])
	r.mu.Lock()
	r.objs[digest] = b
	r.mu.Unlock()
	return digest, len(b)
}

func (r *testRegistry) guard() *netguard.Guard {
	pool := x509.NewCertPool()
	pool.AddCert(r.srv.Certificate())
	return &netguard.Guard{AllowPrivate: true, TLSConfig: &tls.Config{RootCAs: pool}}
}

// pushImage pushes a one-platform (linux/amd64) index, with a BuildKit
// SPDX attestation holding the real postgres:17 document when withSBOM.
// tag makes the index digest unique per test run. Returns the index
// digest (the image id on the containerd store) and the repo digest.
func (r *testRegistry) pushImage(t *testing.T, tag string, withSBOM bool) (imageID, repoDigest string) {
	cfg, cfgSize := r.put(t, []byte(`{"architecture":"amd64","os":"linux"}`))
	man, manSize := r.put(t, map[string]any{"schemaVersion": 2, "mediaType": registry.MediaTypeOCIManifest,
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg, "size": cfgSize},
		"layers": []any{}})
	entries := []any{map[string]any{"mediaType": registry.MediaTypeOCIManifest, "digest": man, "size": manSize,
		"platform": map[string]string{"os": "linux", "architecture": "amd64"}}}
	if withSBOM {
		raw, err := os.ReadFile("../sbom/testdata/postgres17-amd64.spdx.intoto.json")
		if err != nil {
			t.Fatal(err)
		}
		var st map[string]any
		if err := json.Unmarshal(raw, &st); err != nil {
			t.Fatal(err)
		}
		st["subject"] = []any{map[string]any{"name": "pkg:docker/postgres@17",
			"digest": map[string]string{"sha256": strings.TrimPrefix(man, "sha256:")}}}
		blob, blobSize := r.put(t, st)
		attCfg, attCfgSize := r.put(t, []byte(`{}`))
		att, attSize := r.put(t, map[string]any{"schemaVersion": 2, "mediaType": registry.MediaTypeOCIManifest,
			"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": attCfg, "size": attCfgSize},
			"layers": []any{map[string]any{"mediaType": "application/vnd.in-toto+json", "digest": blob, "size": blobSize,
				"annotations": map[string]string{"in-toto.io/predicate-type": "https://spdx.dev/Document"}}}})
		entries = append(entries, map[string]any{"mediaType": registry.MediaTypeOCIManifest, "digest": att, "size": attSize,
			"platform":    map[string]string{"os": "unknown", "architecture": "unknown"},
			"annotations": map[string]string{"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": man}})
	}
	idx, _ := r.put(t, map[string]any{"schemaVersion": 2, "mediaType": registry.MediaTypeOCIIndex, "manifests": entries,
		"annotations": map[string]string{"test": tag}})
	return idx, strings.TrimPrefix(r.srv.URL, "https://") + "/library/postgres@" + idx
}

type imageFixture struct {
	t           *testing.T
	s           *store.Store
	tag         string
	workspaceID string
	hosts       []string
	images      []string
}

func newImageFixture(t *testing.T) *imageFixture {
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
	f := &imageFixture{t: t, s: s, tag: "swtest-" + hex.EncodeToString(b)}
	if err := s.Pool.QueryRow(ctx, `INSERT INTO workspaces (name) VALUES ($1) RETURNING id`,
		f.tag+"@test.invalid").Scan(&f.workspaceID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = s.Pool.Exec(ctx, `DELETE FROM river_job WHERE kind = 'image_sbom' AND args->>'image_id' = ANY($1)`, f.images)
		_, _ = s.Pool.Exec(ctx, `DELETE FROM workspaces WHERE id = $1`, f.workspaceID) // hosts, host_images
		_, _ = s.Pool.Exec(ctx, `DELETE FROM image_sbom_state WHERE image_id = ANY($1)`, f.images)
		_, _ = s.Pool.Exec(ctx, `DELETE FROM container_images WHERE image_id = ANY($1)`, f.images)
	})
	return f
}

// pushHost reports one image on a new host through InsertSnapshot, with
// ingest's AfterWrite (EnqueueAfterIngest on an insert-only client).
func (f *imageFixture) pushHost(imageID, repoDigest string) {
	f.t.Helper()
	ctx := context.Background()
	hostID, err := f.s.CreateHost(ctx, f.workspaceID, f.tag+"-"+string(rune('a'+len(f.hosts))))
	if err != nil {
		f.t.Fatal(err)
	}
	f.hosts = append(f.hosts, hostID)
	f.images = append(f.images, imageID)
	client, err := NewInserter(f.s.Pool)
	if err != nil {
		f.t.Fatal(err)
	}
	set := hostfacts.NewSet(kindDockerImages, hostfacts.HostImagesTable, "", []hostfacts.Row{{
		Key:    imageID,
		Values: []any{imageID, []string{"postgres:17"}, []string{repoDigest}},
		Detail: []any{"linux", "amd64", ""},
		Live:   []any{nil},
	}}, false)
	at := time.Now().UTC().Truncate(time.Second)
	if _, err := f.s.InsertSnapshot(ctx, store.SnapshotInput{
		HostID: hostID, SchemaVersion: 1, CollectedAt: at, InventoryAt: at,
		FactSets:     []hostfacts.Set{set},
		DockerImages: []store.ContainerImage{{ImageID: imageID, OS: "linux", Arch: "amd64"}},
		AfterWrite: func(ctx context.Context, tx pgx.Tx, res store.SnapshotResult) error {
			return EnqueueAfterIngest(ctx, client, tx, hostID, res)
		},
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *imageFixture) jobs(imageID string) int {
	var n int
	_ = f.s.Pool.QueryRow(context.Background(), `SELECT count(*) FROM river_job WHERE kind = 'image_sbom' AND args->>'image_id' = $1`,
		imageID).Scan(&n)
	return n
}

// End to end: ingest enqueues image_sbom once for the fleet, the worker
// fetches the attestation from the registry and stores the list.
func TestImageSBOMJobEndToEnd(t *testing.T) {
	f := newImageFixture(t)
	reg := newTestRegistry(t)
	imageID, repoDigest := reg.pushImage(t, f.tag, true)
	ctx := context.Background()

	f.pushHost(imageID, repoDigest)
	f.pushHost(imageID, repoDigest) // a second host: the unique job absorbs it
	if n := f.jobs(imageID); n != 1 {
		t.Fatalf("%d image_sbom jobs, want 1", n)
	}

	client, err := NewClient(f.s.Pool, f.s, &feeds.Syncer{Store: f.s, Cfg: feeds.DefaultConfig()}, Config{
		DisableMatcherSchedule: true, DisableAlertSchedule: true, DisableMaintenanceSchedule: true,
		Images: ImagesConfig{FetchEnabled: true, DisableSchedule: true,
			Registry: registry.Config{Guard: reg.guard()}},
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
	for deadline := time.Now().Add(20 * time.Second); ref == nil; {
		if time.Now().After(deadline) {
			st, _ := f.s.ServerImageSBOMState(ctx, key)
			t.Fatalf("no ok list; state %+v", st)
		}
		time.Sleep(100 * time.Millisecond)
		if ref, err = f.s.EffectiveImageSBOM(ctx, "", key); err != nil {
			t.Fatal(err)
		}
	}
	if ref.Source != store.SBOMSourceAttestation || ref.OwnerWorkspaceID != "" {
		t.Errorf("list = %+v", ref)
	}
	var tool, toolVersion, distro, release string
	var count int
	if err := f.s.Pool.QueryRow(ctx, `SELECT tool_name, tool_version, distro, release, package_count
		FROM image_sbom_state WHERE id = $1`, ref.SBOMID).Scan(&tool, &toolVersion, &distro, &release, &count); err != nil {
		t.Fatal(err)
	}
	if tool != "docker-scout" || toolVersion != "1.18.1" || distro != "debian" || release != "trixie" {
		t.Errorf("state = %s %s %s %s", tool, toolVersion, distro, release)
	}
	rows, err := f.s.ImageSoftware(ctx, ref.SBOMID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != count || count < 10 {
		t.Fatalf("%d rows, package_count %d", len(rows), count)
	}
	found := false
	for _, r := range rows {
		if r.Ecosystem == "deb" && r.Name == "libc6" {
			found = true
			var src string
			_ = f.s.Pool.QueryRow(ctx, `SELECT source_name FROM software_versions WHERE id = $1`, r.SoftwareID).Scan(&src)
			if r.Distro != "debian" || r.Release != "trixie" || src != "glibc" || len(r.Paths) != 1 || r.Paths[0] != "/var/lib/dpkg/status" {
				t.Errorf("libc6 = %+v, source %q", r, src)
			}
		}
		if r.Ecosystem == "deb" && (r.Name == "glibc" || r.Name == "gcc-14") {
			t.Errorf("source-only entry listed: %+v", r)
		}
	}
	if !found {
		t.Error("libc6 missing")
	}

	// An ok list is never refetched: a new host reporting the image
	// enqueues nothing.
	before := f.jobs(imageID)
	f.pushHost(imageID, repoDigest)
	if n := f.jobs(imageID); n != before {
		t.Errorf("ok image enqueued again (%d -> %d jobs)", before, n)
	}
}

// Failed attempts: what is recorded and whether it is retried.
func TestImageSBOMFailures(t *testing.T) {
	f := newImageFixture(t)
	reg := newTestRegistry(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	fetcher := func(enabled bool) *imagesbom.Fetcher {
		return &imagesbom.Fetcher{Store: f.s, Cfg: imagesbom.Config{Enabled: enabled, Now: func() time.Time { return now },
			Registry: registry.New(registry.Config{Guard: reg.guard()})}}
	}
	state := func(id string) *store.ImageSBOMState {
		st, err := f.s.ServerImageSBOMState(ctx, store.ImageKey{ImageID: id, OS: "linux", Arch: "amd64"})
		if err != nil || st == nil {
			t.Fatalf("state %v %v", st, err)
		}
		return st
	}

	// No attestation: unavailable, not on a timer (server-side Syft's list).
	noSBOM, d := reg.pushImage(t, f.tag+"-none", false)
	f.pushHost(noSBOM, d)
	out, err := fetcher(true).Run(ctx, store.ImageKey{ImageID: noSBOM, OS: "linux", Arch: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if st := state(noSBOM); st.Status != store.SBOMStatusUnavailable || st.Reason != store.SBOMReasonNoAttestation ||
		st.NextAttemptAt != nil || out.Status != st.Status {
		t.Errorf("no attestation: %+v", st)
	}

	// Registry down: error with an exponential retry.
	down, d := reg.pushImage(t, f.tag+"-down", true)
	f.pushHost(down, d)
	reg.down = true
	key := store.ImageKey{ImageID: down, OS: "linux", Arch: "amd64"}
	for i, want := range []time.Duration{30 * time.Minute, time.Hour} {
		if _, err := fetcher(true).Run(ctx, key); err != nil {
			t.Fatal(err)
		}
		st := state(down)
		if st.Status != store.SBOMStatusError || st.NextAttemptAt == nil || !st.NextAttemptAt.Equal(now.Add(want)) ||
			st.Attempts != i+1 || !strings.Contains(st.Reason, "503") {
			t.Errorf("attempt %d: %+v (next %v)", i+1, st, st.NextAttemptAt)
		}
	}
	reg.down = false

	// Fetching disabled: recorded, nothing contacted; picked up by the
	// sweep once enabled.
	off, d := reg.pushImage(t, f.tag+"-off", true)
	f.pushHost(off, d)
	if _, err := fetcher(false).Run(ctx, store.ImageKey{ImageID: off, OS: "linux", Arch: "amd64"}); err != nil {
		t.Fatal(err)
	}
	if st := state(off); st.Reason != store.SBOMReasonFetchDisabled || st.NextAttemptAt != nil {
		t.Errorf("disabled: %+v", st)
	}
	sweep, err := f.s.ImageSBOMSweep(ctx, 100000, true)
	if err != nil {
		t.Fatal(err)
	}
	var sawOff, sawNone bool
	for _, k := range sweep {
		sawOff = sawOff || k.ImageID == off
		sawNone = sawNone || k.ImageID == noSBOM
	}
	if !sawOff || sawNone {
		t.Errorf("sweep: disabled row picked %v, no-attestation row picked %v", sawOff, sawNone)
	}

	// A repo digest pointing at a private address: private or local.
	priv, _ := reg.pushImage(t, f.tag+"-priv", true)
	f.pushHost(priv, "10.1.2.3/library/postgres@"+priv)
	strict := &imagesbom.Fetcher{Store: f.s, Cfg: imagesbom.Config{Enabled: true,
		Registry: registry.New(registry.Config{Guard: &netguard.Guard{}})}}
	if _, err := strict.Run(ctx, store.ImageKey{ImageID: priv, OS: "linux", Arch: "amd64"}); err != nil {
		t.Fatal(err)
	}
	if st := state(priv); st.Status != store.SBOMStatusUnavailable || st.Reason != store.SBOMReasonPrivate {
		t.Errorf("private: %+v", st)
	}
}
