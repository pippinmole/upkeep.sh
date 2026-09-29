package matcher

import (
	"fmt"

	"github.com/pippinmole/upkeep.sh/server/internal/apkversion"
	"github.com/pippinmole/upkeep.sh/server/internal/debversion"
)

// Comparator orders the versions of one package ecosystem. Advisory
// versions and installed versions of an ecosystem use the same one.
type Comparator interface {
	// Validate returns an error if v is not a version of the ecosystem.
	Validate(v string) error
	// Compare returns a negative, zero or positive number as a is older
	// than, equal to or newer than b; an error if either is invalid.
	Compare(a, b string) (int, error)
}

// ecosystem is one assessed package ecosystem.
type ecosystem struct {
	cmp Comparator
	// distros whose advisories are imported for this ecosystem
	// (advisory_affected.distro); language ecosystems will use "".
	distros map[string]bool
}

// ecosystems is the single list of assessed ecosystems, keyed by
// software_versions.ecosystem (the purl type). Adding one (npm, PyPI, Go,
// ...) is a comparator plus its advisory feed; everything not listed
// here is inventoried but "not assessed", never "no vulnerabilities".
var ecosystems = map[string]ecosystem{
	"deb": {debComparator{}, set("debian", "ubuntu")},
	"apk": {apkComparator{}, set("alpine")},
}

// ComparatorFor returns the version comparator of an ecosystem; ok is
// false for ecosystems the matcher does not assess.
func ComparatorFor(eco string) (Comparator, bool) {
	e, ok := ecosystems[eco]
	return e.cmp, ok
}

// Assessed reports whether packages of (ecosystem, distro, release) are
// matched against advisories at all: the ecosystem has a comparator, the
// distro's advisories are imported for it, and a distro-scoped package
// has a release that is still supported. supported is
// distro_releases.supported for (distro, codename = release), false when
// the release isn't in distro_releases: advisories are imported only for
// supported releases, so a release out of support (debian buster) or one
// we don't know matches nothing, and "no vulnerabilities" there means
// nothing. It is ignored for packages without a distro (language
// ecosystems). A package interned with an empty release can't be joined
// to per-release advisories either.
func Assessed(eco, distro, release string, supported bool) bool {
	e, ok := ecosystems[eco]
	if !ok || !e.distros[distro] {
		return false
	}
	return distro == "" || (release != "" && supported)
}

// ReleaseStatus is how a distro release stands for the matcher, from its
// distro_releases row: why an image of that release is or isn't assessed.
type ReleaseStatus string

const (
	ReleaseSupported    ReleaseStatus = "supported"      // advisories imported
	ReleaseOutOfSupport ReleaseStatus = "out_of_support" // known, end of life (supported = false)
	ReleaseUnknown      ReleaseStatus = "unknown"        // not in distro_releases
)

// ReleaseStatusOf maps a distro_releases.supported lookup (nil = no row).
func ReleaseStatusOf(supported *bool) ReleaseStatus {
	switch {
	case supported == nil:
		return ReleaseUnknown
	case *supported:
		return ReleaseSupported
	default:
		return ReleaseOutOfSupport
	}
}

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// debComparator: dpkg ordering (debversion).
type debComparator struct{}

func (debComparator) Validate(v string) error {
	_, err := debversion.Parse(v)
	return err
}

func (debComparator) Compare(a, b string) (int, error) { return debversion.CompareStrings(a, b) }

// apkComparator: apk-tools ordering (apkversion). Invalid versions are
// rejected rather than ordered the way apk orders them, as for deb.
type apkComparator struct{}

func (apkComparator) Validate(v string) error {
	if !apkversion.Valid(v) {
		return fmt.Errorf("apkversion: invalid version %q", v)
	}
	return nil
}

func (c apkComparator) Compare(a, b string) (int, error) {
	if err := c.Validate(a); err != nil {
		return 0, err
	}
	if err := c.Validate(b); err != nil {
		return 0, err
	}
	return apkversion.Compare(a, b), nil
}
