package imagescan

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// Layer extraction into one root filesystem, lowest layer first, the way
// the engine would apply them (OCI image-spec "Applying changesets"):
//
//   - Every write goes through an os.Root, so no entry, and no symlink an
//     earlier entry planted, can reach outside the rootfs: names are
//     cleaned to be relative to it, and a path through a symlink that
//     leaves it (absolute or "../..") fails and the entry is skipped.
//   - Whiteouts: ".wh.<name>" deletes <name> from lower layers,
//     ".wh..wh..opq" empties its directory of lower layers' entries.
//   - Regular files, directories, symlinks and hard links (within the
//     rootfs) are created; device nodes and FIFOs are skipped. Owners,
//     setuid/setgid and times are dropped: files are 0644 (0755 when
//     executable) and directories 0755, owned by the worker, so the tree
//     can always be deleted.
//   - The decompressed stream of all layers together is capped
//     (errTooLarge), counted as it is read, so a small compressed layer
//     can't expand past the disk budget. Tar headers count too, which
//     also bounds the number of entries.

// Layer media types (OCI and Docker v2). Non-distributable variants are
// the same formats.
func layerCompression(mediaType string) (string, bool) {
	t := strings.TrimSpace(strings.SplitN(mediaType, ";", 2)[0])
	switch t {
	case "application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.nondistributable.v1.tar":
		return "", true
	case "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
		"application/vnd.docker.image.rootfs.diff.tar.gzip":
		return "gzip", true
	case "application/vnd.oci.image.layer.v1.tar+zstd", "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd":
		return "zstd", true
	}
	return "", false
}

var errTooLarge = errors.New("image is larger than the uncompressed size limit")

// extractor applies layers to root.
type extractor struct {
	root *os.Root
	// budget is what is left of the uncompressed byte cap.
	budget int64
	// Skipped counts entries not created (devices, escaping paths, …).
	Skipped int
}

// budgetReader counts bytes against the extractor's budget.
type budgetReader struct {
	r io.Reader
	x *extractor
}

func (b *budgetReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.x.budget -= int64(n)
	if b.x.budget < 0 {
		return n, errTooLarge
	}
	return n, err
}

// layer applies one layer blob (compressed as mediaType says).
func (x *extractor) layer(r io.Reader, mediaType string) error {
	comp, ok := layerCompression(mediaType)
	if !ok {
		return fmt.Errorf("%w: layer media type %q", errUnsupported, mediaType)
	}
	switch comp {
	case "gzip":
		zr, err := gzip.NewReader(r)
		if err != nil {
			return fmt.Errorf("layer: gzip: %w", err)
		}
		defer zr.Close()
		r = zr
	case "zstd":
		// Window and memory bounded: the default window cap is 8 MiB
		// for streams; a hostile frame can't make us allocate more.
		zr, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(64<<20))
		if err != nil {
			return fmt.Errorf("layer: zstd: %w", err)
		}
		defer zr.Close()
		r = zr
	}
	tr := tar.NewReader(&budgetReader{r: r, x: x})
	inLayer := map[string]bool{} // entries this layer created (opaque whiteouts keep them)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			if errors.Is(err, errTooLarge) {
				return errTooLarge
			}
			return fmt.Errorf("layer: tar: %w", err)
		}
		if err := x.entry(tr, h, inLayer); err != nil {
			return err
		}
	}
}

// cleanName makes a tar entry name relative to the rootfs ("" = the root).
func cleanName(name string) string {
	return strings.TrimPrefix(path.Clean("/"+name), "/")
}

// entry applies one tar entry. Only errors that make the whole extraction
// pointless (size cap, disk I/O while writing a file) are returned;
// entries that can't be created are skipped.
func (x *extractor) entry(tr *tar.Reader, h *tar.Header, inLayer map[string]bool) error {
	rel := cleanName(h.Name)
	if rel == "" {
		return nil
	}
	dir, base := path.Dir(rel), path.Base(rel)
	if dir == "." {
		dir = ""
	}

	// Whiteouts.
	if base == ".wh..wh..opq" {
		x.opaque(dir, inLayer)
		return nil
	}
	if name, ok := strings.CutPrefix(base, ".wh."); ok {
		if err := x.root.RemoveAll(path.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			x.Skipped++
		}
		return nil
	}

	switch h.Typeflag {
	case tar.TypeDir, tar.TypeReg, tar.TypeSymlink, tar.TypeLink:
	default: // devices, FIFOs, anything else
		x.Skipped++
		return nil
	}
	if dir != "" {
		if err := x.root.MkdirAll(dir, 0o755); err != nil {
			x.Skipped++
			return nil
		}
	}
	// Replace what a lower layer (or an earlier entry) left at the path,
	// except a directory with a directory (merged).
	if fi, err := x.root.Lstat(rel); err == nil {
		if fi.IsDir() && h.Typeflag == tar.TypeDir {
			inLayer[rel] = true
			return nil
		}
		if err := x.root.RemoveAll(rel); err != nil {
			x.Skipped++
			return nil
		}
	}
	inLayer[rel] = true

	switch h.Typeflag {
	case tar.TypeDir:
		if err := x.root.Mkdir(rel, 0o755); err != nil {
			x.Skipped++
		}
	case tar.TypeSymlink:
		// The target is stored as is; os.Root and Syft (directory source
		// with the rootfs as its base) resolve it inside the rootfs.
		if err := x.root.Symlink(h.Linkname, rel); err != nil {
			x.Skipped++
		}
	case tar.TypeLink:
		target := cleanName(h.Linkname)
		if target == "" || x.root.Link(target, rel) != nil {
			x.Skipped++
		}
	case tar.TypeReg:
		mode := fs.FileMode(0o644)
		if h.Mode&0o111 != 0 {
			mode = 0o755
		}
		// O_EXCL: the path was just cleared, so this never opens through
		// a symlink.
		f, err := x.root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			x.Skipped++
			return nil
		}
		_, err = io.Copy(f, tr)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			if errors.Is(err, errTooLarge) {
				return errTooLarge
			}
			return fmt.Errorf("layer: write %s: %w", rel, err)
		}
	}
	return nil
}

// opaque removes dir's entries that lower layers created.
func (x *extractor) opaque(dir string, inLayer map[string]bool) {
	name := dir
	if name == "" {
		name = "."
	}
	f, err := x.root.Open(name)
	if err != nil {
		return
	}
	ents, err := f.ReadDir(-1)
	f.Close()
	if err != nil {
		return
	}
	for _, e := range ents {
		p := path.Join(dir, e.Name())
		if !inLayer[p] {
			_ = x.root.RemoveAll(p)
		}
	}
}
