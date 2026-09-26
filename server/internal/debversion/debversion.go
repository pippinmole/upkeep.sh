// Package debversion implements Debian package version parsing and
// ordering with the exact semantics of `dpkg --compare-versions`
// (deb-version(7); a port of dpkg's parseversion and verrevcmp).
//
// Advisory matching (docs/DOMAIN_MODEL.md §2.5) compares installed source
// versions against advisory fixed versions here, in Go. Postgres never
// compares versions: plain text ordering gets `1.10 < 1.9`, `1.0~rc1 > 1.0`
// and epochs (`1:2.0` vs `3.0`) wrong, and backport suffixes such as
// `~deb11u1`, `+deb12u1`, `ubuntu0.22.04.1` and `+esm1` are neither semver
// nor strings.
//
// # Format
//
//	[epoch:]upstream_version[-debian_revision]
//
// The epoch is a decimal integer and defaults to 0. The revision starts
// after the LAST hyphen; without a hyphen there is no revision (which
// compares equal to revision "0"). Leading and trailing blanks (space, tab)
// are trimmed, as dpkg does.
//
// # Strict vs lenient parsing
//
// dpkg distinguishes two classes of problems:
//
//   - Errors, which dpkg refuses outright (it will not install such a
//     package): empty version, embedded blanks, an empty/non-numeric/
//     negative/too-big epoch, nothing after the epoch colon, an empty
//     upstream version, an empty revision after a trailing hyphen.
//   - Warnings, which dpkg reports but otherwise accepts (and orders
//     normally): upstream not starting with a digit, and characters outside
//     the allowed sets (upstream: alphanumerics and `.+~-:`; revision:
//     alphanumerics and `.+~`).
//
// [Parse] is lenient: it rejects only the error class, exactly like dpkg.
// Every version dpkg has ever installed therefore parses, which matters
// because installed packages must never fail to parse (a parse failure
// would silently drop a package from vulnerability matching), and real
// archives do contain warning-class versions from old or third-party
// packages. [ParseStrict] additionally rejects the warning class, for
// callers that want to flag malformed input (e.g. data-quality checks on
// advisory feeds) rather than accept it.
//
// Comparison is total over every Version that [Parse] returns, including
// warning-class ones, and matches dpkg's verrevcmp byte for byte.
package debversion

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// Version is a parsed Debian version. The zero value is "0" (epoch 0,
// empty upstream, no revision) only for comparison purposes; it is not a
// valid parse result.
type Version struct {
	Epoch    int    // 0..math.MaxInt32, as in dpkg
	Upstream string // never empty for a parsed version
	Revision string // "" when the version had no hyphen
}

// ParseError describes why a version string was rejected.
type ParseError struct {
	Input  string
	Reason string
	// Warning is true for problems dpkg only warns about (rejected by
	// ParseStrict, accepted by Parse).
	Warning bool
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("debversion: invalid version %q: %s", e.Input, e.Reason)
}

// ErrInvalid is matched by errors.Is for every *ParseError.
var ErrInvalid = errors.New("debversion: invalid version")

// Is makes errors.Is(err, ErrInvalid) true for parse errors.
func (e *ParseError) Is(target error) bool { return target == ErrInvalid }

// Parse parses s with dpkg's own acceptance rules: it fails only where dpkg
// fails, and accepts (without error) versions dpkg merely warns about. See
// the package documentation.
func Parse(s string) (Version, error) {
	v, _, err := parse(s)
	if err != nil {
		return Version{}, err // non-nil *ParseError; never a typed nil
	}
	return v, nil
}

// ParseStrict is Parse but also rejects versions dpkg warns about (an
// upstream version not starting with a digit, invalid characters). The
// returned *ParseError has Warning set in that case.
func ParseStrict(s string) (Version, error) {
	v, warn, err := parse(s)
	if err != nil {
		return Version{}, err
	}
	if warn != nil {
		return Version{}, warn
	}
	return v, nil
}

// MustParse is Parse that panics on error. For tests and constants.
func MustParse(s string) Version {
	v, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return v
}

func isBlank(c byte) bool { return c == ' ' || c == '\t' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// parse mirrors dpkg's parseversion (lib/dpkg/parsehelp.c). It returns the
// version plus, separately, the first warning-class problem if any.
func parse(input string) (Version, *ParseError, *ParseError) {
	fail := func(reason string) (Version, *ParseError, *ParseError) {
		return Version{}, nil, &ParseError{Input: input, Reason: reason}
	}

	s := strings.TrimLeft(input, " \t")
	if s == "" {
		return fail("version string is empty")
	}
	end := 0
	for end < len(s) && !isBlank(s[end]) {
		end++
	}
	if strings.TrimLeft(s[end:], " \t") != "" {
		return fail("version string has embedded spaces")
	}
	s = s[:end]

	var v Version
	if colon := strings.IndexByte(s, ':'); colon >= 0 {
		epoch, reason := parseEpoch(s[:colon])
		if reason != "" {
			return fail(reason)
		}
		if colon+1 == len(s) {
			return fail("nothing after colon in version number")
		}
		v.Epoch = epoch
		s = s[colon+1:]
	}

	if hyphen := strings.LastIndexByte(s, '-'); hyphen >= 0 {
		v.Upstream, v.Revision = s[:hyphen], s[hyphen+1:]
		if v.Revision == "" {
			return fail("revision number is empty")
		}
	} else {
		v.Upstream = s
	}
	if v.Upstream == "" {
		return fail("version number is empty")
	}

	var warn *ParseError
	switch {
	case !isDigit(v.Upstream[0]):
		warn = &ParseError{Input: input, Reason: "version number does not start with digit", Warning: true}
	case strings.IndexFunc(v.Upstream, func(r rune) bool { return !validUpstream(r) }) >= 0:
		warn = &ParseError{Input: input, Reason: "invalid character in version number", Warning: true}
	case strings.IndexFunc(v.Revision, func(r rune) bool { return !validRevision(r) }) >= 0:
		warn = &ParseError{Input: input, Reason: "invalid character in revision number", Warning: true}
	}
	return v, warn, nil
}

func validUpstream(r rune) bool {
	return r < 0x80 && (isDigit(byte(r)) || isAlpha(byte(r)) || strings.ContainsRune(".-+~:", r))
}

func validRevision(r rune) bool {
	return r < 0x80 && (isDigit(byte(r)) || isAlpha(byte(r)) || strings.ContainsRune(".+~", r))
}

// parseEpoch mirrors dpkg's strtol-based epoch check: an optional sign,
// then at least one digit, running exactly up to the colon; the value must
// be in 0..INT_MAX ("-0" is therefore accepted, as dpkg does).
func parseEpoch(s string) (int, string) {
	digits := s
	neg := false
	if digits != "" && (digits[0] == '+' || digits[0] == '-') {
		neg = digits[0] == '-'
		digits = digits[1:]
	}
	n := 0
	for n < len(digits) && isDigit(digits[n]) {
		n++
	}
	if n == 0 {
		return 0, "epoch in version is empty"
	}
	if n != len(digits) {
		return 0, "epoch in version is not number"
	}
	digits = strings.TrimLeft(digits, "0")
	var val int64
	for i := 0; i < len(digits); i++ {
		val = val*10 + int64(digits[i]-'0')
		if val > math.MaxInt32 {
			if neg {
				return 0, "epoch in version is negative"
			}
			return 0, "epoch in version is too big"
		}
	}
	if neg && val != 0 {
		return 0, "epoch in version is negative"
	}
	return int(val), ""
}

// String returns the canonical form: the epoch is written only when it is
// non-zero or when the upstream version or (warning-class) revision
// contains a colon, so the result always re-parses to the same Version; the revision is written
// only when present. Blanks and a redundant "0:" are therefore not
// preserved.
func (v Version) String() string {
	var b strings.Builder
	if v.Epoch != 0 || strings.ContainsRune(v.Upstream, ':') || strings.ContainsRune(v.Revision, ':') {
		fmt.Fprintf(&b, "%d:", v.Epoch)
	}
	b.WriteString(v.Upstream)
	if v.Revision != "" {
		b.WriteByte('-')
		b.WriteString(v.Revision)
	}
	return b.String()
}

// Compare orders a and b like dpkg: -1 if a < b, 0 if equal, +1 if a > b.
// Epochs compare numerically, then the upstream versions, then the
// revisions, each with dpkg's verrevcmp.
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

// Compare is the method form of Compare(v, o).
func (v Version) Compare(o Version) int { return Compare(v, o) }

// Equal reports whether v and o are equal under dpkg ordering (e.g. "1.0",
// "0:1.0" and "1.0-0" are all equal).
func (v Version) Equal(o Version) bool { return Compare(v, o) == 0 }

// CompareStrings parses both versions with Parse and compares them.
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

// order is dpkg's per-character weight for non-digit runs: '~' sorts before
// everything (including the end of the string, weight 0), letters sort by
// ASCII value, and everything else sorts after all letters.
//
// Bytes >= 0x80 are weighted as on amd64, where dpkg's `char` is signed
// (c+256 with c negative, i.e. 128..255): after letters, before ASCII
// punctuation. Only warning-class versions contain such bytes.
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

// verrevcmp is dpkg's verrevcmp: alternate non-digit runs (compared with
// order, where running off the end weighs 0) and digit runs (compared
// numerically with leading zeros ignored, of any length).
func verrevcmp(a, b string) int {
	i, j := 0, 0
	// weight is order() of s[k], and 0 past the end of s (C's NUL
	// terminator). An embedded NUL byte, which dpkg can never see, weighs
	// as ordinary punctuation instead.
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
