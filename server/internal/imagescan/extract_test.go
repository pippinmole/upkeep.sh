package imagescan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const (
	mtGzip = "application/vnd.oci.image.layer.v1.tar+gzip"
	mtTar  = "application/vnd.oci.image.layer.v1.tar"
)

type tarEntry struct {
	name, body, link string
	typ              byte
	mode             int64
}

func layerTar(t *testing.T, gz bool, ents ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := &buf
	var zw *gzip.Writer
	tw := tar.NewWriter(w)
	if gz {
		zw = gzip.NewWriter(w)
		tw = tar.NewWriter(zw)
	}
	for _, e := range ents {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Linkname: e.link, Mode: e.mode, Size: int64(len(e.body))}
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if h.Typeflag != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if zw != nil {
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func newExtractor(t *testing.T, budget int64) (*extractor, string) {
	t.Helper()
	dir := t.TempDir()
	rootfs := filepath.Join(dir, "rootfs")
	if err := os.Mkdir(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return &extractor{root: root, budget: budget}, rootfs
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

func TestExtractLayersAndWhiteouts(t *testing.T) {
	x, rootfs := newExtractor(t, 1<<20)
	l1 := layerTar(t, true,
		tarEntry{name: "etc/", typ: tar.TypeDir},
		tarEntry{name: "etc/os-release", body: "ID=debian\n"},
		tarEntry{name: "etc/gone", body: "x"},
		tarEntry{name: "opt/old/a", body: "a"},
		tarEntry{name: "usr/bin/tool", body: "#!", mode: 0o4755},
		tarEntry{name: "usr/bin/link", typ: tar.TypeLink, link: "usr/bin/tool"},
		tarEntry{name: "bin", typ: tar.TypeSymlink, link: "usr/bin"},
		tarEntry{name: "dev/null", typ: tar.TypeChar},
		tarEntry{name: "run/fifo", typ: tar.TypeFifo},
	)
	l2 := layerTar(t, false,
		tarEntry{name: "etc/.wh.gone"},
		tarEntry{name: "opt/old/.wh..wh..opq"},
		tarEntry{name: "opt/old/b", body: "b"},
		tarEntry{name: "etc/os-release", body: "ID=alpine\n"},
	)
	if err := x.layer(bytes.NewReader(l1), mtGzip); err != nil {
		t.Fatal(err)
	}
	if err := x.layer(bytes.NewReader(l2), mtTar); err != nil {
		t.Fatal(err)
	}

	if b, _ := os.ReadFile(filepath.Join(rootfs, "etc/os-release")); string(b) != "ID=alpine\n" {
		t.Errorf("os-release = %q, want the upper layer's", b)
	}
	if exists(filepath.Join(rootfs, "etc/gone")) {
		t.Error("whiteout didn't remove etc/gone")
	}
	if exists(filepath.Join(rootfs, "opt/old/a")) || !exists(filepath.Join(rootfs, "opt/old/b")) {
		t.Error("opaque whiteout: want a removed, b kept")
	}
	fi, err := os.Stat(filepath.Join(rootfs, "usr/bin/tool"))
	if err != nil || fi.Mode().Perm() != 0o755 || fi.Mode()&os.ModeSetuid != 0 {
		t.Errorf("usr/bin/tool mode = %v (%v), want 0755 without setuid", fi.Mode(), err)
	}
	if !exists(filepath.Join(rootfs, "usr/bin/link")) {
		t.Error("hard link missing")
	}
	if l, _ := os.Readlink(filepath.Join(rootfs, "bin")); l != "usr/bin" {
		t.Errorf("bin -> %q", l)
	}
	if exists(filepath.Join(rootfs, "dev/null")) || exists(filepath.Join(rootfs, "run/fifo")) {
		t.Error("device / fifo created")
	}
	if x.Skipped != 2 {
		t.Errorf("skipped = %d, want 2", x.Skipped)
	}
}

func TestExtractStaysInRoot(t *testing.T) {
	x, rootfs := newExtractor(t, 1<<20)
	outside := filepath.Dir(rootfs)
	l := layerTar(t, false,
		tarEntry{name: "../../escape", body: "x"},              // cleaned to /escape
		tarEntry{name: "/abs/file", body: "x"},                 // cleaned to /abs/file
		tarEntry{name: "up", typ: tar.TypeSymlink, link: ".."}, // escapes when followed
		tarEntry{name: "up/through-up", body: "x"},
		tarEntry{name: "etc", typ: tar.TypeSymlink, link: "/"},
		tarEntry{name: "etc/passwd", body: "x"},
		tarEntry{name: "hl", typ: tar.TypeLink, link: "../../../etc/hosts"},
		tarEntry{name: "up", typ: tar.TypeSymlink, link: ".."}, // replaced, not followed
	)
	if err := x.layer(bytes.NewReader(l), mtTar); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(rootfs, "escape")) || !exists(filepath.Join(rootfs, "abs/file")) {
		t.Error("cleaned names not created inside the root")
	}
	for _, p := range []string{"escape", "through-up", "passwd"} {
		if exists(filepath.Join(outside, p)) {
			t.Errorf("%s written outside the root", p)
		}
	}
	if fi, err := os.Lstat(filepath.Join(rootfs, "hl")); err == nil && fi.Mode().IsRegular() {
		// A hard link to /etc/hosts (cleaned to the root's etc/hosts, which
		// doesn't exist) must not have been made to the real one.
		t.Error("hard link outside the root created")
	}
}

func TestExtractSizeCap(t *testing.T) {
	x, _ := newExtractor(t, 4096)
	l := layerTar(t, true, tarEntry{name: "big", body: string(bytes.Repeat([]byte("a"), 64<<10))})
	if err := x.layer(bytes.NewReader(l), mtGzip); !errors.Is(err, errTooLarge) {
		t.Fatalf("err = %v, want errTooLarge", err)
	}
}

func TestExtractUnsupported(t *testing.T) {
	x, _ := newExtractor(t, 4096)
	err := x.layer(bytes.NewReader(nil), "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip")
	if !errors.Is(err, errUnsupported) {
		t.Fatalf("err = %v, want errUnsupported", err)
	}
}
