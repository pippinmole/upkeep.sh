// Package sbom reads SBOM documents (SPDX 2.x JSON, CycloneDX JSON) into
// what an image package list needs (docs/decisions/container-image-vulnerabilities.md):
// each package's purl and where in the image it was found, the image's OS from its os-release, and the generating tool.
// Mapping purls to interned software keys is purl.Map's job.
//
// The documents come from several generators, which differ in ways that
// matter for matching; see spdx.go for Docker Scout's (Docker Official
// Images) and Syft's conventions.
package sbom

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/purl"
)

// Formats (registry.FormatSPDX / FormatCycloneDX use the same strings).
const (
	FormatSPDX      = "spdx-json"
	FormatCycloneDX = "cyclonedx-json"
)

// Document is the part of an SBOM an image package list is built from.
type Document struct {
	Format string
	// ToolName / ToolVersion: the scanner that generated it ("docker-scout"
	// "1.18.1", "syft" "v1.51.0"), not the build tool wrapping it.
	ToolName, ToolVersion string
	// Created is when the document says it was generated (zero = unknown).
	Created time.Time
	// OS is the image's os-release as far as the document tells: its
	// operating-system entry, else the distro qualifiers most of its distro
	// packages carry. Zero when none (scratch, distroless).
	OS       purl.OSRelease
	Packages []Package
	// Skipped counts package entries without a usable purl.
	Skipped int
}

// Package is one package entry.
type Package struct {
	PURL purl.PURL
	// Paths where in the image the package was found ("/var/lib/dpkg/status",
	// "/usr/local/bin/gosu"), absolute, sorted, de-duplicated.
	Paths []string
}

// Parse reads a document of the given format.
func Parse(format string, b []byte) (*Document, error) {
	switch format {
	case FormatSPDX:
		return parseSPDX(b)
	case FormatCycloneDX:
		return parseCycloneDX(b)
	}
	return nil, fmt.Errorf("sbom: unsupported format %q", format)
}

// maxPathsPerPackage bounds the paths kept per package (a Go binary's
// modules all point at the binary; a deb has one status file).
const maxPathsPerPackage = 16

// packageDBs are the package manager databases distro packages are read
// from. A distro package's paths are only these (its other evidence, such
// as /usr/share/doc/<pkg>/copyright, says nothing more).
var packageDBs = []string{
	"/var/lib/dpkg/status", "/var/lib/dpkg/status.d/",
	"/lib/apk/db/installed",
	"/var/lib/rpm/", "/usr/lib/sysimage/rpm/",
	"/var/lib/pacman/local/",
}

func isPackageDB(p string) bool {
	for _, db := range packageDBs {
		if p == db || (strings.HasSuffix(db, "/") && strings.HasPrefix(p, db)) {
			return true
		}
	}
	return false
}

// cleanPaths makes paths absolute, keeps only package databases for
// distro types, sorts, de-duplicates and caps them.
func cleanPaths(typ string, in []string) []string {
	var out []string
	distro := purl.DistroScoped(typ)
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if distro && !isPackageDB(p) {
			continue
		}
		out = append(out, p)
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > maxPathsPerPackage {
		out = out[:maxPathsPerPackage]
	}
	return out
}

// toolRE splits "name-version" where the version starts at the first
// '-' followed by a digit or "v<digit>": "docker-scout-1.18.1",
// "syft-v1.51.0", "buildkit-0.16.0-tianon".
var toolRE = regexp.MustCompile(`^(.+?)-(v?\d.*)$`)

func splitTool(s string) (name, version string) {
	s = strings.TrimSpace(s)
	if m := toolRE.FindStringSubmatch(s); m != nil {
		return m[1], m[2]
	}
	return s, ""
}

// pickTool returns the first tool that isn't BuildKit (which only wraps
// the scanner that did the work), else the first tool.
func pickTool(tools [][2]string) (name, version string) {
	for _, t := range tools {
		if !strings.EqualFold(t[0], "buildkit") {
			return t[0], t[1]
		}
	}
	if len(tools) > 0 {
		return tools[0][0], tools[0][1]
	}
	return "", ""
}

// osFromPURLs is the image's OS by majority of its distro packages'
// qualifiers, for documents without an operating-system entry:
//
//	os_name=debian&os_version=13&os_distro=trixie   Docker Scout
//	distro=debian-12, distro=alpine-3.20.3          Syft, Trivy
func osFromPURLs(pkgs []Package) purl.OSRelease {
	votes := map[purl.OSRelease]int{}
	for _, p := range pkgs {
		if !purl.DistroScoped(p.PURL.Type) {
			continue
		}
		if n := p.PURL.Qualifier("os_name"); n != "" {
			votes[purl.OSRelease{ID: strings.ToLower(n), VersionID: p.PURL.Qualifier("os_version"),
				VersionCodename: strings.ToLower(p.PURL.Qualifier("os_distro"))}]++
		} else if o, ok := purl.OSFromQualifier(p.PURL); ok {
			votes[o]++
		}
	}
	var best purl.OSRelease
	n := 0
	for o, c := range votes {
		if c > n || (c == n && cmp.Compare(o.ID+o.VersionID+o.VersionCodename, best.ID+best.VersionID+best.VersionCodename) < 0) {
			best, n = o, c
		}
	}
	return best
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}
