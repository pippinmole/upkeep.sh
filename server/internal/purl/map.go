package purl

import (
	"errors"
	"fmt"
	"strings"

	"github.com/pippinmole/upkeep.sh/server/internal/inventory"
)

// Package is one purl mapped to the interned software key: Ecosystem,
// Distro and Release scope it like inventory.Set, Item carries name,
// version, arch and source exactly as host ingest would store them.
type Package struct {
	Ecosystem, Distro, Release string
	Item                       inventory.Item
	// KnownType is false for purl types not in the table: still stored
	// (inventory first), under the purl type as the ecosystem.
	KnownType bool
	// DistroFromPURL: the image had no usable os-release and the scope
	// came from the purl's distro qualifier instead.
	DistroFromPURL bool
}

// Map maps a parsed purl to the interned software key. osr is the image's
// os-release (zero when unknown); ix resolves version numbers to codenames
// for codename-keyed distros.
//
// The rules match host ingest (ingest.defaultPackage), so an image package
// and the same package on a host intern to the same software_versions row
// and match identically:
//
//   - version: the purl version, with an "epoch" qualifier folded in as
//     "N:" (epoch 0 is dropped) for deb/rpm, since dpkg and rpm print the
//     epoch in the version and hosts store it that way. A version that
//     already contains the epoch (Syft writes "1:2.3-4" percent-encoded)
//     is kept as is.
//   - arch: the "arch" qualifier ("" when absent).
//   - source: the "upstream" qualifier where the type has one (deb source,
//     apk origin, rpm source rpm); a source without a version takes the
//     binary version. Otherwise source = binary name/version, inferred.
//   - distro/release: from os-release for distro-scoped types (ReleaseFor),
//     falling back to the purl's distro qualifier; empty for the rest.
func Map(p PURL, osr OSRelease, ix ReleaseIndex) (Package, error) {
	rule, known := knownTypes[p.Type]
	if !known {
		rule = typeRule{Ecosystem: p.Type, Name: slashName}
	}
	pkg := Package{Ecosystem: rule.Ecosystem, KnownType: known}

	name := p.Name
	if rule.Name != nil {
		name = rule.Name(p.Namespace, p.Name)
	}
	version := p.Version
	if version == "" {
		return pkg, fmt.Errorf("purl %s/%s: no version", p.Type, name)
	}
	if rule.Epoch {
		var err error
		if version, err = withEpoch(version, p.Qualifier("epoch")); err != nil {
			return pkg, fmt.Errorf("purl %s/%s: %w", p.Type, name, err)
		}
	}
	it := inventory.Item{Name: name, Version: version, Arch: p.Qualifier("arch")}
	if rule.Upstream != nil && p.Qualifier("upstream") != "" {
		if src, srcv, ok := rule.Upstream(p.Qualifier("upstream")); ok {
			it.Source, it.SourceVersion = src, srcv
			if it.SourceVersion == "" {
				it.SourceVersion = version
			}
		}
	}
	if it.Source == "" {
		it.Source, it.SourceVersion, it.SourceInferred = name, version, true
	}
	pkg.Item = it

	if rule.DistroScoped {
		os := osr
		if os.ID == "" {
			if q, ok := OSFromQualifier(p); ok {
				os, pkg.DistroFromPURL = q, true
			}
		}
		pkg.Distro, pkg.Release = strings.ToLower(os.ID), ReleaseFor(os, ix)
	}

	for _, f := range []string{pkg.Ecosystem, pkg.Distro, pkg.Release, it.Name, it.Version, it.Arch, it.Source, it.SourceVersion} {
		if strings.IndexByte(f, 0) >= 0 { // Postgres text can't hold NUL
			return pkg, errors.New("purl: NUL byte in a field")
		}
	}
	return pkg, nil
}

// MapString parses and maps in one step.
func MapString(s string, osr OSRelease, ix ReleaseIndex) (Package, error) {
	p, err := Parse(s)
	if err != nil {
		return Package{}, err
	}
	return Map(p, osr, ix)
}

func withEpoch(version, epoch string) (string, error) {
	if epoch == "" || epoch == "0" || strings.Contains(version, ":") {
		return version, nil
	}
	for _, c := range epoch {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("bad epoch %q", epoch)
		}
	}
	return epoch + ":" + version, nil
}
