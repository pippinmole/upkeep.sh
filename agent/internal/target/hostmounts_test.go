package target

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, name, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The layout a non-recursive /host bind gives on a host with a separate
// /var and a /run tmpfs: /host/var and /host/run are empty mountpoint
// directories, and the nested directories the collectors read come from
// the extra root.
func TestHostFSOverlay(t *testing.T) {
	host, extra := t.TempDir(), t.TempDir()
	write(t, host, "etc/os-release", "ID=ubuntu\n")
	for _, d := range []string{"var", "run"} {
		if err := os.MkdirAll(filepath.Join(host, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, extra, "var/lib/dpkg/status", "Package: a\n")
	write(t, extra, "run/systemd/system/foo.service", "[Unit]\n")
	// Not in ExtraPaths: must never be served from the extra root.
	write(t, extra, "run/reboot-required", "")

	l := NewLocalWithExtra(host, extra, "")
	fsys := l.FS()

	if b, err := fs.ReadFile(fsys, "var/lib/dpkg/status"); err != nil || string(b) != "Package: a\n" {
		t.Fatalf("dpkg status via extra root: %q, %v", b, err)
	}
	if b, err := fs.ReadFile(fsys, "etc/os-release"); err != nil || string(b) != "ID=ubuntu\n" {
		t.Fatalf("os-release via host root: %q, %v", b, err)
	}
	if es, err := fs.ReadDir(fsys, "run/systemd/system"); err != nil || len(es) != 1 {
		t.Fatalf("run/systemd/system: %v, %v", es, err)
	}
	// Parents come from the base, where the nested mount is hidden.
	if es, err := fs.ReadDir(fsys, "run"); err != nil || len(es) != 0 {
		t.Fatalf("run should list the empty base dir: %v, %v", es, err)
	}
	if _, err := fs.Stat(fsys, "run/reboot-required"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("run/reboot-required must not come from the extra root: %v", err)
	}
	// var/lib/apt isn't bound in this fixture: falls back to the base.
	if _, err := fs.Stat(fsys, "var/lib/apt"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("var/lib/apt: %v", err)
	}
	if _, err := fsys.Open("../etc/passwd"); err == nil {
		t.Fatal("invalid path accepted")
	}
}

// Without an extra root (or with none of ExtraPaths in it), the FS is the
// plain host root: bare metal, and an older compose file.
func TestHostFSFallsBack(t *testing.T) {
	host := t.TempDir()
	write(t, host, "var/lib/dpkg/status", "x")
	for _, extra := range []string{"", t.TempDir(), filepath.Join(host, "missing")} {
		l := NewLocalWithExtra(host, extra, "")
		if _, ok := l.FS().(*hostFS); ok {
			t.Errorf("extra %q: want plain DirFS", extra)
		}
		if b, err := fs.ReadFile(l.FS(), "var/lib/dpkg/status"); err != nil || string(b) != "x" {
			t.Errorf("extra %q: %q, %v", extra, b, err)
		}
	}
}

func TestNotVisible(t *testing.T) {
	errNX := &fs.PathError{Op: "open", Path: "var/lib/dpkg/status", Err: fs.ErrNotExist}

	container := NewLocalWithExtra("/host", "/host-extra", "/proc")
	err := NotVisible(container, errNX)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("hint must keep ErrNotExist: %v", err)
	}
	for _, want := range []string{"var/lib/dpkg/status not visible under /host or /host-extra/var/lib/dpkg", "check the agent's mounts"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q missing %q", err, want)
		}
	}
	if err := NotVisible(container, &fs.PathError{Op: "open", Path: "etc/passwd", Err: fs.ErrNotExist}); !strings.HasPrefix(err.Error(), "etc/passwd not visible under /host;") {
		t.Errorf("etc/passwd: %v", err)
	}

	// Bare metal: genuinely missing, no mount hint.
	if err := NotVisible(NewLocal("/", "/proc"), errNX); err != errNX {
		t.Errorf("bare metal: %v", err)
	}
	// Other errors pass through.
	perm := &fs.PathError{Op: "open", Path: "x", Err: fs.ErrPermission}
	if err := NotVisible(container, perm); err != perm {
		t.Errorf("permission error rewritten: %v", err)
	}
	if err := NotVisible(container, nil); err != nil {
		t.Errorf("nil: %v", err)
	}
}
