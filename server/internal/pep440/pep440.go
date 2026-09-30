// Package pep440 implements Python package version parsing and ordering
// per PEP 440 (the "Version specifiers" specification), with the
// semantics of pypa/packaging's packaging.version.Version, whose own test
// vectors are testdata/.
//
// Advisory matching (docs/DOMAIN_MODEL.md §2.5) compares installed PyPI
// versions against OSV PyPI ranges (type ECOSYSTEM) here, in Go, as
// debversion and apkversion do for distro packages. Written in-tree: the
// rules are one regular expression and one ordering, and no small,
// maintained Go module implements them without pulling in more.
//
// # Format
//
//	[N!]N(.N)*[{a|b|rc}N][.postN][.devN][+local]
//
// with the spellings PEP 440 normalises: a leading "v", "alpha"/"beta",
// "c"/"pre"/"preview" for rc, "rev"/"r" or "-N" for post, optional
// separators and numbers, any letter case, surrounding whitespace.
// Legacy (non-PEP 440) versions are invalid, as in packaging >= 22.
//
// # Ordering
//
// Epoch, then the release numbers with trailing zeros ignored ("1.0" ==
// "1.0.0"), then: a dev release of a final version (1.0.dev0) before its
// pre-releases (1.0a0), pre-releases a < b < rc before the final, post
// releases after it, a dev release of any of those just before it, and
// the local version last (none < any; segments compared in order,
// numbers numerically and above strings, a shorter prefix first).
package pep440

import (
	"fmt"
	"regexp"
	"strings"
)

// Version is a parsed PEP 440 version. Numbers are kept as digit strings
// without leading zeros (PEP 440 puts no bound on them).
type Version struct {
	Epoch   string
	Release []string
	Pre     string // "", "a", "b" or "rc"
	PreN    string
	Post    bool
	PostN   string
	Dev     bool
	DevN    string
	Local   []string // lowercased segments
}

// versionRe is packaging's VERSION_PATTERN, applied to an ASCII-lowercased
// string (so non-ASCII letters never match a class, as with re.ASCII).
var versionRe = regexp.MustCompile(`^v?` +
	`(?:([0-9]+)!)?` + // epoch
	`([0-9]+(?:\.[0-9]+)*)` + // release
	`(?:[-_.]?(alpha|a|beta|b|preview|pre|c|rc)[-_.]?([0-9]+)?)?` + // pre
	`(?:-([0-9]+)|[-_.]?(post|rev|r)[-_.]?([0-9]+)?)?` + // post
	`(?:[-_.]?(dev)[-_.]?([0-9]+)?)?` + // dev
	`(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`) // local

// Parse parses a PEP 440 version.
func Parse(s string) (Version, error) {
	var v Version
	m := versionRe.FindStringSubmatch(asciiLower(strings.TrimSpace(s)))
	if m == nil {
		return v, fmt.Errorf("pep440: invalid version %q", s)
	}
	v.Epoch = num(m[1])
	for _, r := range strings.Split(m[2], ".") {
		v.Release = append(v.Release, num(r))
	}
	if m[3] != "" {
		v.Pre, v.PreN = map[string]string{"alpha": "a", "a": "a", "beta": "b", "b": "b",
			"c": "rc", "pre": "rc", "preview": "rc", "rc": "rc"}[m[3]], num(m[4])
	}
	switch {
	case m[5] != "":
		v.Post, v.PostN = true, num(m[5])
	case m[6] != "":
		v.Post, v.PostN = true, num(m[7])
	}
	if m[8] != "" {
		v.Dev, v.DevN = true, num(m[9])
	}
	if m[10] != "" {
		v.Local = strings.FieldsFunc(m[10], func(r rune) bool { return r == '-' || r == '_' || r == '.' })
		for i, l := range v.Local {
			if isDigits(l) {
				v.Local[i] = num(l)
			}
		}
	}
	return v, nil
}

// Valid reports whether s is a valid PEP 440 version.
func Valid(s string) bool {
	_, err := Parse(s)
	return err == nil
}

// String is the normalised form (packaging's str(Version)).
func (v Version) String() string {
	var b strings.Builder
	if v.Epoch != "0" {
		b.WriteString(v.Epoch + "!")
	}
	b.WriteString(strings.Join(v.Release, "."))
	if v.Pre != "" {
		b.WriteString(v.Pre + v.PreN)
	}
	if v.Post {
		b.WriteString(".post" + v.PostN)
	}
	if v.Dev {
		b.WriteString(".dev" + v.DevN)
	}
	if len(v.Local) > 0 {
		b.WriteString("+" + strings.Join(v.Local, "."))
	}
	return b.String()
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
// than b (packaging's _cmpkey order).
func Compare(a, b Version) int {
	if c := cmpNum(a.Epoch, b.Epoch); c != 0 {
		return c
	}
	if c := cmpRelease(a.Release, b.Release); c != 0 {
		return c
	}
	if c := cmpPre(a, b); c != 0 {
		return c
	}
	// Post: none < any.
	if c := cmpOpt(a.Post, a.PostN, b.Post, b.PostN, -1); c != 0 {
		return c
	}
	// Dev: any < none.
	if c := cmpOpt(a.Dev, a.DevN, b.Dev, b.DevN, 1); c != 0 {
		return c
	}
	return cmpLocal(a.Local, b.Local)
}

// preRank places the pre-release part: a dev release of a final version
// (no pre, no post) sorts below every pre-release, a final above them.
func preRank(v Version) (rank int, n string) {
	switch {
	case v.Pre == "" && !v.Post && v.Dev:
		return 0, "" // -Infinity
	case v.Pre == "":
		return 4, "" // +Infinity
	}
	return map[string]int{"a": 1, "b": 2, "rc": 3}[v.Pre], v.PreN
}

func cmpPre(a, b Version) int {
	ra, na := preRank(a)
	rb, nb := preRank(b)
	if ra != rb {
		return cmpInt(ra, rb)
	}
	return cmpNum(na, nb)
}

// cmpOpt compares an optional number; absent sorts as absent (-1 =
// below every number, +1 = above).
func cmpOpt(ha bool, na string, hb bool, nb string, absent int) int {
	switch {
	case ha && hb:
		return cmpNum(na, nb)
	case ha == hb:
		return 0
	case !ha:
		return absent
	}
	return -absent
}

func cmpRelease(a, b []string) int {
	a, b = trimZeros(a), trimZeros(b)
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := cmpNum(a[i], b[i]); c != 0 {
			return c
		}
	}
	return cmpInt(len(a), len(b))
}

func trimZeros(r []string) []string {
	for len(r) > 0 && r[len(r)-1] == "0" {
		r = r[:len(r)-1]
	}
	return r
}

// cmpLocal: no local < any local; segment by segment, a number above a
// string, numbers numerically, strings lexically; a prefix first.
func cmpLocal(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		an, bn := isDigits(a[i]), isDigits(b[i])
		var c int
		switch {
		case an && bn:
			c = cmpNum(a[i], b[i])
		case an:
			c = 1
		case bn:
			c = -1
		default:
			c = strings.Compare(a[i], b[i])
		}
		if c != 0 {
			return c
		}
	}
	return cmpInt(len(a), len(b))
}

// cmpNum compares digit strings without leading zeros.
func cmpNum(a, b string) int {
	if len(a) != len(b) {
		return cmpInt(len(a), len(b))
	}
	return strings.Compare(a, b)
}

// num strips leading zeros ("" and "000" are 0).
func num(s string) string {
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}

func isDigits(s string) bool {
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

func asciiLower(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
