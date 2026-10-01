package imagescan

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/source/directorysource"
	_ "modernc.org/sqlite" // Syft's rpm cataloger reads newer (sqlite) rpmdbs through database/sql

	"github.com/pippinmole/upkeep.sh/server/internal/purl"
	"github.com/pippinmole/upkeep.sh/server/internal/sbom"
)

// ToolName is what server-side lists record as their generator
// (image_sbom_state.tool_name); the version is Syft's module version.
const ToolName = "syft"

// Result is what the catalog child writes to stdout (JSON): the image's
// os-release as Syft identified it and every package with a purl.
type Result struct {
	ToolName    string         `json:"tool_name"`
	ToolVersion string         `json:"tool_version"`
	OS          purl.OSRelease `json:"os"`
	Packages    []sbom.Entry   `json:"packages"`
	// NoPURL counts packages Syft found without a purl.
	NoPURL int `json:"no_purl"`
}

// Catalog runs Syft over an extracted image root filesystem. It is the
// catalog child's work (RunChild); the parent never calls it, so Syft's
// CPU and memory use stay inside the child's limits.
//
// The rootfs is scanned as a directory source with the directory as the
// symlink base, so absolute symlinks resolve inside it, but with the
// catalogers Syft uses for images ("image" tag: installed packages, not
// lock files and manifests), which is what `syft <image>` would find in
// the squashed image. File cataloging (digests, metadata) is off: only
// packages are needed.
func Catalog(ctx context.Context, rootfs string, parallelism int) (*Result, error) {
	src, err := directorysource.New(directorysource.Config{Path: rootfs, Base: rootfs})
	if err != nil {
		return nil, fmt.Errorf("syft source: %w", err)
	}
	defer src.Close()

	cfg := syft.DefaultCreateSBOMConfig().
		WithoutFiles().
		WithCatalogerSelection(cataloging.NewSelectionRequest().WithDefaults(pkgcataloging.ImageTag))
	if parallelism > 0 {
		cfg = cfg.WithParallelism(parallelism)
	}
	s, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return nil, fmt.Errorf("syft: %w", err)
	}

	res := &Result{ToolName: ToolName, ToolVersion: cfg.ToolVersion}
	if d := s.Artifacts.LinuxDistribution; d != nil {
		res.OS = purl.OSRelease{
			ID: d.ID, VersionID: d.VersionID, VersionCodename: d.VersionCodename,
			PrettyName: d.PrettyName,
		}
	}
	for _, p := range s.Artifacts.Packages.Sorted() {
		if p.PURL == "" {
			res.NoPURL++
			continue
		}
		var paths []string
		for _, l := range p.Locations.ToSlice() {
			paths = append(paths, l.RealPath)
		}
		slices.Sort(paths)
		res.Packages = append(res.Packages, sbom.Entry{PURL: p.PURL, Paths: slices.Compact(paths)})
	}
	slices.SortStableFunc(res.Packages, func(a, b sbom.Entry) int {
		return cmp.Or(cmp.Compare(a.PURL, b.PURL), slices.Compare(a.Paths, b.Paths))
	})
	return res, nil
}
