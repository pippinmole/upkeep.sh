// Package imagescan catalogs a public container image on the server:
// it pulls the image's platform layers by digest through our registry
// client, extracts them into a temporary root filesystem and runs Syft
// (as a library, in a resource-limited child process) over it
// (docs/tasks/phase-2a-image-vulns.md "Server-side Syft",
// docs/decisions/container-image-vulnerabilities.md). It is the fallback
// for images whose registry has no SBOM attestation; internal/imagesbom
// stores its result like an attestation's, with source server-syft.
//
//	registry.ResolveImage ─> DownloadBlob (each layer: temp file, digest
//	  verified) ─> extract into <dir>/scan-*/rootfs (os.Root, whiteouts,
//	  caps) ─> child `worker syft-catalog <rootfs>` (GOMAXPROCS,
//	  GOMEMLIMIT, RSS watchdog, killed on timeout) ─> Result ─> RemoveAll
//
// Syft never touches the network: it only sees the extracted directory.
// All network access is the registry client's (netguard, digests,
// timeouts, token and redirect rules).
package imagescan

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/registry"
)

// Defaults for Config's zero values.
const (
	DefaultMaxCompressedBytes   = 2 << 30 // 2 GiB of layer blobs
	DefaultMaxUncompressedBytes = 8 << 30 // 8 GiB extracted
	DefaultTimeout              = 20 * time.Minute
	DefaultCPUs                 = 1
	DefaultMemoryBytes          = 2 << 30 // 2 GiB RSS for the catalog child
	// DirPrefix names each scan's temporary directory under Config.Dir;
	// SweepDir removes leftovers with it.
	DirPrefix = "scan-"
)

// Config configures a Scanner.
type Config struct {
	// Registry is the shared registry client (required).
	Registry *registry.Client
	// Dir holds each scan's temporary directory ("" =
	// DefaultDir()). Only one worker process may use it: SweepDir
	// deletes whatever scans it finds there.
	Dir string
	// MaxCompressedBytes caps the image's layer blobs together;
	// MaxUncompressedBytes the extracted layers together (disk use is at
	// most one compressed layer plus the extracted ones).
	MaxCompressedBytes, MaxUncompressedBytes int64
	// Timeout is the wall clock for one image: pull, extract, catalog.
	Timeout time.Duration
	// CPUs is the catalog child's GOMAXPROCS (and Syft's parallelism).
	CPUs int
	// MemoryBytes is the catalog child's memory limit: GOMEMLIMIT at 80%
	// of it, and killed when its RSS exceeds it (Linux).
	MemoryBytes int64
	// Command is the catalog child's argv without the rootfs (nil = this
	// executable with CatalogCommand). Tests point it at the test binary.
	Command []string
}

// CatalogCommand is the hidden worker subcommand the child runs.
const CatalogCommand = "syft-catalog"

// DefaultDir is where scans go by default.
func DefaultDir() string { return filepath.Join(os.TempDir(), "upkeep-image-scan") }

// Scanner scans images. Safe for concurrent use.
type Scanner struct{ cfg Config }

// New returns a Scanner for cfg.
func New(cfg Config) *Scanner {
	cfg.Dir = cmp.Or(cfg.Dir, DefaultDir())
	cfg.MaxCompressedBytes = cmp.Or(cfg.MaxCompressedBytes, DefaultMaxCompressedBytes)
	cfg.MaxUncompressedBytes = cmp.Or(cfg.MaxUncompressedBytes, DefaultMaxUncompressedBytes)
	cfg.Timeout = cmp.Or(cfg.Timeout, DefaultTimeout)
	cfg.CPUs = cmp.Or(cfg.CPUs, DefaultCPUs)
	cfg.MemoryBytes = cmp.Or(cfg.MemoryBytes, DefaultMemoryBytes)
	return &Scanner{cfg: cfg}
}

// Timeout is the per-image wall clock (for the job's own timeout).
func (s *Scanner) Timeout() time.Duration { return s.cfg.Timeout }

// ErrorKind classifies a scan failure that isn't a registry error.
type ErrorKind int

const (
	// KindTooLarge: over MaxCompressedBytes / MaxUncompressedBytes.
	KindTooLarge ErrorKind = iota + 1
	// KindUnsupported: a layer format we can't read (e.g. Windows
	// foreign layers).
	KindUnsupported
	// KindTimeout: the image took longer than Timeout.
	KindTimeout
	// KindMemory: the catalog child went over MemoryBytes.
	KindMemory
	// KindFailed: anything else (disk I/O, the child crashed). Worth
	// retrying later.
	KindFailed
)

// Error is a scan failure of our own (registry failures are
// *registry.Error, returned as is).
type Error struct {
	Kind ErrorKind
	Err  error
}

func (e *Error) Error() string { return "image scan: " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

var errUnsupported = errors.New("unsupported image")

// Scan pulls and catalogs the platform p of the image ref names
// (imageID as for registry.FetchSBOM). Every temporary file is removed
// before it returns, whatever happened.
func (s *Scanner) Scan(ctx context.Context, ref registry.Ref, p registry.Platform, imageID string) (res *Result, err error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	defer func() {
		if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			err = &Error{Kind: KindTimeout, Err: fmt.Errorf("took longer than %s", s.cfg.Timeout)}
		}
	}()

	img, err := s.cfg.Registry.ResolveImage(ctx, ref, p, imageID)
	if err != nil {
		return nil, err
	}
	var total int64
	for _, l := range img.Layers {
		total += l.Size
		if _, ok := layerCompression(l.MediaType); !ok {
			return nil, &Error{Kind: KindUnsupported, Err: fmt.Errorf("layer media type %q", l.MediaType)}
		}
	}
	if total > s.cfg.MaxCompressedBytes {
		return nil, &Error{Kind: KindTooLarge, Err: fmt.Errorf("layers are %d bytes compressed, over the %d byte limit",
			total, s.cfg.MaxCompressedBytes)}
	}

	if err := os.MkdirAll(s.cfg.Dir, 0o700); err != nil {
		return nil, &Error{Kind: KindFailed, Err: err}
	}
	dir, err := os.MkdirTemp(s.cfg.Dir, DirPrefix)
	if err != nil {
		return nil, &Error{Kind: KindFailed, Err: err}
	}
	defer func() {
		if rerr := os.RemoveAll(dir); rerr != nil {
			log.Printf("image scan: removing %s: %v", dir, rerr)
		}
	}()

	rootfs := filepath.Join(dir, "rootfs")
	if err := s.pull(ctx, img, dir, rootfs); err != nil {
		return nil, err
	}
	return s.catalog(ctx, rootfs)
}

// pull downloads each layer to a temporary file and applies it to rootfs.
func (s *Scanner) pull(ctx context.Context, img *registry.Image, dir, rootfs string) error {
	if err := os.Mkdir(rootfs, 0o755); err != nil {
		return &Error{Kind: KindFailed, Err: err}
	}
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return &Error{Kind: KindFailed, Err: err}
	}
	defer root.Close()
	x := &extractor{root: root, budget: s.cfg.MaxUncompressedBytes}
	for i, l := range img.Layers {
		if err := s.applyLayer(ctx, img, l, filepath.Join(dir, fmt.Sprintf("layer-%d", i)), x); err != nil {
			return err
		}
	}
	return nil
}

func (s *Scanner) applyLayer(ctx context.Context, img *registry.Image, l registry.Descriptor, file string, x *extractor) error {
	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return &Error{Kind: KindFailed, Err: err}
	}
	defer func() {
		f.Close()
		os.Remove(file)
	}()
	if err := s.cfg.Registry.DownloadBlob(ctx, img.Ref, l, s.cfg.MaxCompressedBytes, f); err != nil {
		var re *registry.Error
		if errors.As(err, &re) {
			return err
		}
		return &Error{Kind: KindFailed, Err: fmt.Errorf("layer %s: %w", l.Digest, err)}
	}
	if _, err := f.Seek(0, 0); err != nil {
		return &Error{Kind: KindFailed, Err: err}
	}
	switch err := x.layer(f, l.MediaType); {
	case err == nil:
		return nil
	case errors.Is(err, errTooLarge):
		return &Error{Kind: KindTooLarge, Err: fmt.Errorf("layers are over the %d byte uncompressed limit", s.cfg.MaxUncompressedBytes)}
	case errors.Is(err, errUnsupported):
		return &Error{Kind: KindUnsupported, Err: err}
	default:
		return &Error{Kind: KindFailed, Err: fmt.Errorf("layer %s: %w", l.Digest, err)}
	}
}

// SweepDir removes scan directories left in dir by a previous process
// (killed mid-scan). Run it once at worker start, before any scan.
func SweepDir(dir string) error {
	dir = cmp.Or(dir, DefaultDir())
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), DirPrefix) {
			errs = append(errs, os.RemoveAll(filepath.Join(dir, e.Name())))
		}
	}
	return errors.Join(errs...)
}
