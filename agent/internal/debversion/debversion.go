// Package debversion orders Debian package versions like
// `dpkg --compare-versions` (deb-version(7)).
//
// It is a minimal copy of server/internal/debversion (a separate Go
// module): only what the agent needs to tell which installed kernel is
// newest (collector.CollectRebootRequired). The server's package is the
// reference implementation with the full parse rules and test corpus;
// keep the comparison here byte-for-byte the same as its verrevcmp.
package debversion

import (
	"errors"
	"math"
	"strconv"
	"strings"
)

// Version is a parsed Debian version: [epoch:]upstream[-revision].
type Version struct {
	Epoch    int
	Upstream string
	Revision string // "" without a hyphen (equal to "0")
}

// ErrInvalid is returned for versions dpkg itself refuses.
var ErrInvalid = errors.New("debversion: invalid version")

// Parse accepts every version dpkg accepts (it is lenient about the
// characters dpkg only warns about) and rejects the rest.
func Parse(s string) (Version, error) {
	s = strings.Trim(s, " \t")
	if s == "" || strings.ContainsAny(s, " \t") {
		return Version{}, ErrInvalid
	}
	var v Version
	if colon := strings.IndexByte(s, ':'); colon >= 0 {
		e, err := strconv.Atoi(s[:colon])
		if err != nil || e < 0 || e > math.MaxInt32 || colon+1 == len(s) {
			return Version{}, ErrInvalid
		}
		v.Epoch, s = e, s[colon+1:]
	}
	if hyphen := strings.LastIndexByte(s, '-'); hyphen >= 0 {
		v.Upstream, v.Revision = s[:hyphen], s[hyphen+1:]
		if v.Revision == "" {
			return Version{}, ErrInvalid
		}
	} else {
		v.Upstream = s
	}
	if v.Upstream == "" {
		return Version{}, ErrInvalid
	}
	return v, nil
}

// Compare returns -1, 0 or +1 as a is older than, equal to or newer than b.
func Compare(a, b Version) int {
	switch {
	case a.Epoch < b.Epoch:
		return -1
	case a.Epoch > b.Epoch:
		return 1
	}
	if c := verrevcmp(a.Upstream, b.Upstream); c != 0 {
		return c
	}
	return verrevcmp(a.Revision, b.Revision)
}

// CompareStrings parses and compares two versions.
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

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// order is dpkg's weight for non-digit characters: '~' before everything
// (even the end of the string), then letters, then everything else.
func order(c byte) int {
	switch {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	case c >= 0x80:
		return int(int8(c)) + 256
	default:
		return int(c) + 256
	}
}

// verrevcmp is dpkg's verrevcmp: alternating non-digit runs (by order)
// and digit runs (numerically, leading zeros ignored).
func verrevcmp(a, b string) int {
	i, j := 0, 0
	weight := func(s string, k int) int {
		if k < len(s) {
			return order(s[k])
		}
		return 0
	}
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := weight(a, i), weight(b, j)
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		firstDiff := 0
		for i < len(a) && j < len(b) && isDigit(a[i]) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
