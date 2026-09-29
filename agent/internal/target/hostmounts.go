package target

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"
)

// The Docker deployment binds the host's / at /host NON-recursively
// (bind-recursive=disabled), so no socket on a nested mount (/run is a
// tmpfs holding docker.sock, containerd, systemd's private socket and
// D-Bus) is reachable from the agent. A non-recursive bind also hides
// every other nested mount, so the few directories the collectors read
// that live on one (always /run; /var when it is its own filesystem) are
// bound read-only on their own, under ExtraRoot instead of inside /host:
// a mountpoint inside the read-only /host bind would have to already
// exist on the host's root filesystem (it doesn't when /var or /run is a
// separate mount, since the runtime can't mkdir through a read-only
// bind), while ExtraRoot lives in the container's own filesystem.
//
// ExtraPaths is that list, relative to the host root. It must match the
// "/host-extra" binds in agent/docker-compose.example.yml and the
// dashboard's docker run command (checked by TestComposeExtraBinds and the
// web test). Never add run itself, run/systemd (its private socket), or
// var wholesale: sockets live there.
var ExtraPaths = []string{
	"var/lib/dpkg",       // deb_packages, arch, reboot_required (kernels)
	"var/lib/apt",        // unattended_upgrades (periodic stamps, lists mtime)
	"run/systemd/system", // systemd_services (runtime units)
}

// DefaultExtraRoot is where the Docker deployment mounts ExtraPaths.
const DefaultExtraRoot = "/host-extra"

// hostFS is the local host's filesystem: base (the host root) with
// ExtraPaths served from extraRoot wherever extraRoot has them. A path is
// taken from the extra root only when it is one of the mounted prefixes or
// below it, so listing a parent ("run", "var/lib") still shows the base
// view, where the nested mount is hidden.
type hostFS struct {
	base     fs.FS
	extra    fs.FS
	prefixes []string // ExtraPaths present under extraRoot
}

// newHostFS returns os.DirFS(hostRoot), overlaid with the ExtraPaths that
// exist as directories under extraRoot (none when extraRoot is empty).
func newHostFS(hostRoot, extraRoot string) fs.FS {
	base := os.DirFS(hostRoot)
	if extraRoot == "" {
		return base
	}
	h := &hostFS{base: base, extra: os.DirFS(extraRoot)}
	for _, p := range ExtraPaths {
		if fi, err := os.Stat(path.Join(extraRoot, p)); err == nil && fi.IsDir() {
			h.prefixes = append(h.prefixes, p)
		}
	}
	if len(h.prefixes) == 0 {
		return base
	}
	return h
}

func (h *hostFS) pick(name string) fs.FS {
	for _, p := range h.prefixes {
		if name == p || strings.HasPrefix(name, p+"/") {
			return h.extra
		}
	}
	return h.base
}

func (h *hostFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	return h.pick(name).Open(name)
}

func (h *hostFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	return fs.ReadDir(h.pick(name), name)
}

func (h *hostFS) Stat(name string) (fs.FileInfo, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}
	return fs.Stat(h.pick(name), name)
}

func (h *hostFS) ReadLink(name string) (string, error) {
	if !fs.ValidPath(name) {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrInvalid}
	}
	return fs.ReadLink(h.pick(name), name)
}

func (h *hostFS) Lstat(name string) (fs.FileInfo, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "lstat", Path: name, Err: fs.ErrInvalid}
	}
	return fs.Lstat(h.pick(name), name)
}

var (
	_ fs.ReadDirFS  = (*hostFS)(nil)
	_ fs.StatFS     = (*hostFS)(nil)
	_ fs.ReadLinkFS = (*hostFS)(nil)
)

// MissingHinter is an optional capability: a target that can say why an
// expected path isn't visible (e.g. the agent's mounts), for error
// messages. See NotVisible.
type MissingHinter interface {
	MissingHint(name string) string
}

// NotVisible wraps err (an fs.ErrNotExist for name, a path every host of
// this kind has) with the target's explanation, so a misconfigured mount
// reads as such instead of as an empty or odd result. Other errors, and
// targets without a hint, return err unchanged.
func NotVisible(t Target, name string, err error) error {
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	h, ok := t.(MissingHinter)
	if !ok {
		return err
	}
	if hint := h.MissingHint(name); hint != "" {
		return &notVisibleError{msg: hint, err: err}
	}
	return err
}

type notVisibleError struct {
	msg string
	err error
}

func (e *notVisibleError) Error() string { return e.msg }
func (e *notVisibleError) Unwrap() error { return e.err }
