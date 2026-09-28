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
// matched against advisories at all: the ecosystem has a comparator and
// the distro's advisories are imported for it, and a distro-scoped
// package has a release (one interned with an empty release can't be
// joined to per-release advisories).
//
// Whether that release is still supported (distro_releases.supported,
// i.e. not end-of-life) is data, not code: callers that need it join
// distro_releases on (distro, codename = release).
func Assessed(eco, distro, release string) bool {
	e, ok := ecosystems[eco]
	if !ok || !e.distros[distro] {
		return false
	}
	return distro == "" || release != ""
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
