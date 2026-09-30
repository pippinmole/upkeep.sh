// Package npmversion implements npm package version validation and
// ordering with the semantics of node-semver (`semver.compare` in loose
// mode), the library npm itself uses. Its test vectors are node-semver's
// own comparison and equality fixtures (testdata/).
//
// Advisory matching (docs/DOMAIN_MODEL.md §2.5) compares installed npm
// versions against OSV npm ranges (type SEMVER) here, in Go, as
// debversion and apkversion do for distro packages.
//
// Written in-tree rather than as a dependency: node-semver's ordering is
// SemVer 2.0's (which golang.org/x/mod/semver also implements), but its
// accepted syntax is not: it requires all three numbers ("1.2" is
// invalid, x/mod accepts it), accepts a leading "v"/"=" and, loosely,
// a prerelease without its "-" ("1.2.3beta"), and caps numbers at
// JavaScript's MAX_SAFE_INTEGER. The rules fit in this file.
//
// # Format (loose)
//
//	[v=\s]* MAJOR.MINOR.PATCH [-]PRERELEASE? (+BUILD)?
//
// Numbers compare numerically. A version with a prerelease is lower than
// the same version without one; prerelease identifiers compare pairwise:
// numeric ones numerically, numeric < alphanumeric, alphanumeric ones by
// ASCII; a shorter list that is a prefix of a longer one is lower. Build
// metadata is ignored.
package npmversion

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	maxLength      = 256       // node-semver MAX_LENGTH
	maxSafeInteger = 1<<53 - 1 // Number.MAX_SAFE_INTEGER
)

// Version is a parsed npm version.
type Version struct {
	Major, Minor, Patch uint64
	Pre                 []string // prerelease identifiers
	Build               []string // ignored for ordering
}

// Parse parses a version as node-semver does in loose mode.
func Parse(s string) (Version, error) {
	var v Version
	if len(s) > maxLength {
		return v, fmt.Errorf("npmversion: version longer than %d", maxLength)
	}
	in := strings.TrimSpace(s)
	in = strings.TrimLeft(in, "v= \t\n\r\f\v")
	// MAJOR.MINOR.PATCH
	var nums [3]uint64
	for i := range 3 {
		j := 0
		for j < len(in) && in[j] >= '0' && in[j] <= '9' {
			j++
		}
		if j == 0 {
			return v, fmt.Errorf("npmversion: invalid version %q", s)
		}
		n, err := strconv.ParseUint(in[:j], 10, 64)
		if err != nil || n > maxSafeInteger {
			return v, fmt.Errorf("npmversion: number too big in %q", s)
		}
		nums[i] = n
		in = in[j:]
		if i < 2 {
			if in == "" || in[0] != '.' {
				return v, fmt.Errorf("npmversion: invalid version %q", s)
			}
			in = in[1:]
		}
	}
	v.Major, v.Minor, v.Patch = nums[0], nums[1], nums[2]
	rest, build, hasBuild := strings.Cut(in, "+")
	if hasBuild {
		v.Build = strings.Split(build, ".")
		for _, id := range v.Build {
			if id == "" || !alnumHyphen(id) {
				return v, fmt.Errorf("npmversion: invalid build in %q", s)
			}
		}
	}
	if rest != "" {
		rest = strings.TrimPrefix(rest, "-") // optional in loose mode
		v.Pre = strings.Split(rest, ".")
		for _, id := range v.Pre {
			if id == "" || !alnumHyphen(id) {
				return v, fmt.Errorf("npmversion: invalid prerelease in %q", s)
			}
		}
	}
	return v, nil
}

// Valid reports whether s is a valid (loose) npm version.
func Valid(s string) bool {
	_, err := Parse(s)
	return err == nil
}

// CompareStrings parses and compares a and b.
func CompareStrings(a, b string) (int, error) {
	va, err := Parse(a)
	if err != nil {
		return 0, err
	}
	vb, err := Parse(b)
	if err != nil {
		return 0, err
	}
	return Compare(va, vb), nil
}

// Compare returns -1, 0 or +1 as a is older than, equal to or newer
// than b (node-semver compareMain, then comparePre; build ignored).
func Compare(a, b Version) int {
	if c := cmpUint(a.Major, b.Major); c != 0 {
		return c
	}
	if c := cmpUint(a.Minor, b.Minor); c != 0 {
		return c
	}
	if c := cmpUint(a.Patch, b.Patch); c != 0 {
		return c
	}
	switch {
	case len(a.Pre) == 0 && len(b.Pre) == 0:
		return 0
	case len(a.Pre) == 0:
		return 1
	case len(b.Pre) == 0:
		return -1
	}
	for i := 0; ; i++ {
		switch {
		case i == len(a.Pre) && i == len(b.Pre):
			return 0
		case i == len(a.Pre):
			return -1
		case i == len(b.Pre):
			return 1
		}
		if c := compareIdentifiers(a.Pre[i], b.Pre[i]); c != 0 {
			return c
		}
	}
}

// compareIdentifiers: numeric identifiers compare numerically and sort
// before alphanumeric ones, which compare by ASCII.
func compareIdentifiers(a, b string) int {
	an, bn := numeric(a), numeric(b)
	switch {
	case an && bn:
		// Numbers of any length: compare without leading zeros by length,
		// then digits (node-semver converts them to Numbers; beyond
		// MAX_SAFE_INTEGER it keeps strings, which this also orders).
		a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
		if len(a) != len(b) {
			return cmpInt(len(a), len(b))
		}
		return strings.Compare(a, b)
	case an:
		return -1
	case bn:
		return 1
	}
	return strings.Compare(a, b)
}

func numeric(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func alnumHyphen(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-') {
			return false
		}
	}
	return true
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpInt(a, b int) int { return cmpUint(uint64(a), uint64(b)) }
