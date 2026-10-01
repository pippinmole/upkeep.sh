package imagescan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/netguard"
	"github.com/pippinmole/upkeep.sh/server/internal/registry"
)

// The test binary doubles as the catalog child (Config.Command).
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == CatalogCommand {
		if os.Getenv("IMAGESCAN_TEST_CHILD_SLEEP") != "" {
			time.Sleep(time.Minute)
		}
		if err := RunChild(os.Args[2:]); err != nil {
			os.Stderr.WriteString(err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// fakeRegistry serves manifests and blobs by digest over TLS.
type fakeRegistry struct {
	srv     *httptest.Server
	mu      sync.Mutex
	objs    map[string][]byte
	corrupt string // digest served with wrong content
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	r := &fakeRegistry{objs: map[string][]byte{}}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		d := req.URL.Path[strings.LastIndexByte(req.URL.Path, '/')+1:]
		b, ok := r.objs[d]
		if !ok {
			http.NotFound(w, req)
			return
		}
		if d == r.corrupt {
			b = append([]byte("x"), b[1:]...)
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *fakeRegistry) put(t *testing.T, v any) (string, int64) {
	b, ok := v.([]byte)
	if !ok {
		var err error
		if b, err = json.Marshal(v); err != nil {
			t.Fatal(err)
		}
	}
	s := sha256.Sum256(b)
	d := "sha256:" + hex.EncodeToString(s[:])
	r.mu.Lock()
	r.objs[d] = b
	r.mu.Unlock()
	return d, int64(len(b))
}

func (r *fakeRegistry) client() *registry.Client {
	pool := x509.NewCertPool()
	pool.AddCert(r.srv.Certificate())
	return registry.New(registry.Config{Guard: &netguard.Guard{AllowPrivate: true, TLSConfig: &tls.Config{RootCAs: pool}}})
}

const apkDB = `C:Q1aaaaaaaaaaaaaaaaaaaaaaaaaaa=
P:musl
V:1.2.5-r10
A:aarch64
o:musl
F:lib
R:ld-musl-aarch64.so.1

C:Q1bbbbbbbbbbbbbbbbbbbbbbbbbbb=
P:busybox-binsh
V:1.37.0-r18
A:aarch64
o:busybox
F:bin
R:sh

`

// pushImage pushes an Alpine-like linux/arm64 image: a base layer and one
// that deletes a file, in an index. Returns the image id (index digest)
// and the parsed repo digest.
func (r *fakeRegistry) pushImage(t *testing.T, tag string) (string, registry.Ref) {
	l1 := layerTar(t, true,
		tarEntry{name: "etc/os-release", body: "ID=alpine\nVERSION_ID=3.24.1\nPRETTY_NAME=\"Alpine Linux v3.24\"\n"},
		tarEntry{name: "lib/apk/db/installed", body: apkDB},
		tarEntry{name: "lib/ld-musl-aarch64.so.1", body: "elf"},
		tarEntry{name: "bin/sh", body: "#!", mode: 0o755},
		tarEntry{name: "tmp/junk", body: "x"},
	)
	l2 := layerTar(t, true, tarEntry{name: "tmp/.wh.junk"})
	var layers []any
	for _, l := range [][]byte{l1, l2} {
		d, n := r.put(t, l)
		layers = append(layers, map[string]any{"mediaType": mtGzip, "digest": d, "size": n})
	}
	cfg, cfgSize := r.put(t, []byte(`{"architecture":"arm64","os":"linux"}`))
	man, manSize := r.put(t, map[string]any{
		"schemaVersion": 2, "mediaType": registry.MediaTypeOCIManifest,
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg, "size": cfgSize},
		"layers": layers,
	})
	idx, _ := r.put(t, map[string]any{
		"schemaVersion": 2, "mediaType": registry.MediaTypeOCIIndex,
		"manifests": []any{map[string]any{
			"mediaType": registry.MediaTypeOCIManifest, "digest": man, "size": manSize,
			"platform": map[string]string{"os": "linux", "architecture": "arm64"},
		}},
		"annotations": map[string]string{"tag": tag},
	})
	ref, err := registry.ParseRepoDigest(strings.TrimPrefix(r.srv.URL, "https://") + "/library/alpine@" + idx)
	if err != nil {
		t.Fatal(err)
	}
	return idx, ref
}

var arm64 = registry.Platform{OS: "linux", Architecture: "arm64"}

func newTestScanner(t *testing.T, reg *fakeRegistry, cfg Config) (*Scanner, string) {
	dir := t.TempDir()
	cfg.Registry, cfg.Dir = reg.client(), dir
	cfg.Command = []string{os.Args[0], CatalogCommand}
	return New(cfg), dir
}

func assertEmpty(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Errorf("%d entries left in the scan dir (%s…)", len(ents), ents[0].Name())
	}
}

func TestScan(t *testing.T) {
	reg := newFakeRegistry(t)
	imageID, ref := reg.pushImage(t, "ok")
	s, dir := newTestScanner(t, reg, Config{})

	res, err := s.Scan(context.Background(), ref, arm64, imageID)
	if err != nil {
		t.Fatal(err)
	}
	assertEmpty(t, dir)
	if res.ToolName != "syft" || res.ToolVersion == "" || res.OS.ID != "alpine" || res.OS.VersionID != "3.24.1" {
		t.Errorf("result = %s %s %+v", res.ToolName, res.ToolVersion, res.OS)
	}
	var purls []string
	for _, p := range res.Packages {
		purls = append(purls, p.PURL)
		if len(p.Paths) == 0 || p.Paths[0] != "/lib/apk/db/installed" {
			t.Errorf("%s paths = %v", p.PURL, p.Paths)
		}
	}
	want := []string{
		"pkg:apk/alpine/busybox-binsh@1.37.0-r18?arch=aarch64&distro=alpine-3.24.1&upstream=busybox",
		"pkg:apk/alpine/musl@1.2.5-r10?arch=aarch64&distro=alpine-3.24.1",
	}
	if strings.Join(purls, " ") != strings.Join(want, " ") {
		t.Errorf("purls = %v, want %v", purls, want)
	}

	// Same image, same list.
	again, err := s.Scan(context.Background(), ref, arm64, imageID)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(res)
	b, _ := json.Marshal(again)
	if !bytes.Equal(a, b) {
		t.Error("second scan differs")
	}
}

func TestScanFailures(t *testing.T) {
	reg := newFakeRegistry(t)
	imageID, ref := reg.pushImage(t, "fail")
	ctx := context.Background()
	kind := func(err error) ErrorKind {
		var e *Error
		if errors.As(err, &e) {
			return e.Kind
		}
		return 0
	}

	s, dir := newTestScanner(t, reg, Config{MaxCompressedBytes: 100})
	if _, err := s.Scan(ctx, ref, arm64, imageID); kind(err) != KindTooLarge {
		t.Errorf("compressed cap: %v", err)
	}
	assertEmpty(t, dir)

	s, dir = newTestScanner(t, reg, Config{MaxUncompressedBytes: 2048})
	if _, err := s.Scan(ctx, ref, arm64, imageID); kind(err) != KindTooLarge {
		t.Errorf("uncompressed cap: %v", err)
	}
	assertEmpty(t, dir)

	s, dir = newTestScanner(t, reg, Config{})
	if _, err := s.Scan(ctx, ref, arm64, "sha256:"+strings.Repeat("0", 64)); registry.KindOf(err) != registry.KindMismatch {
		t.Errorf("other image id: %v", err)
	}
	if _, err := s.Scan(ctx, ref, registry.Platform{OS: "linux", Architecture: "s390x"}, imageID); registry.KindOf(err) != registry.KindMismatch {
		t.Errorf("missing platform: %v", err)
	}

	// A layer whose content doesn't match its digest.
	img, err := reg.client().ResolveImage(ctx, ref, arm64, imageID)
	if err != nil {
		t.Fatal(err)
	}
	reg.mu.Lock()
	reg.corrupt = img.Layers[0].Digest
	reg.mu.Unlock()
	if _, err := s.Scan(ctx, ref, arm64, imageID); registry.KindOf(err) != registry.KindTransient ||
		!strings.Contains(err.Error(), "digest mismatch") {
		t.Errorf("corrupt layer: %v", err)
	}
	reg.mu.Lock()
	reg.corrupt = ""
	reg.mu.Unlock()
	assertEmpty(t, dir)

	// The child is killed at the deadline; its rootfs is still removed.
	t.Setenv("IMAGESCAN_TEST_CHILD_SLEEP", "1")
	s, dir = newTestScanner(t, reg, Config{Timeout: 2 * time.Second})
	start := time.Now()
	if _, err := s.Scan(ctx, ref, arm64, imageID); kind(err) != KindTimeout {
		t.Errorf("timeout: %v", err)
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Errorf("timeout took %s", d)
	}
	assertEmpty(t, dir)
}

func TestSweepDir(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"scan-1/rootfs/etc", "scan-2", "other"} {
		if err := os.MkdirAll(dir+"/"+p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := SweepDir(dir); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 || ents[0].Name() != "other" {
		t.Errorf("left %v", ents)
	}
	if err := SweepDir(dir + "/missing"); err != nil {
		t.Errorf("missing dir: %v", err)
	}
}
