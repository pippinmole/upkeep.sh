// Package apkversion implements Alpine package version validation and
// ordering with the semantics of apk-tools (`apk version -t`; a port of
// apk-tools src/version.c, 3.0.x, whose test vectors are
// testdata/version.data).
//
// Advisory matching (docs/DOMAIN_MODEL.md §2.5) compares installed apk
// versions against Alpine advisory fixed versions here, in Go, just as
// debversion does for dpkg versions.
//
// # Format
//
//	digit{.digit}...{letter}{_suffix{digits}}...{~hash}{-rN}
//
// Numbers compare numerically, except that a dotted component with a
// leading zero on either side compares as a string ("1.02" < "1.1"). A
// single letter may follow the numbers ("1.2a" > "1.2"). Suffixes order
// _alpha < _beta < _pre < _rc < (none) < _cvs < _svn < _git < _hg < _p.
// "~hash" is a commit hash (compared as a string) and "-rN" the package
// revision. When one version runs out of tokens first, the longer one is
// greater unless its next token is a pre-release suffix; so "1.0" <
// "1.0-r0" < "1.0-r1", and "1.0_rc1" < "1.0".
//
// # Invalid versions
//
// [Valid] reports what apk accepts. [Compare] is total and never panics:
// like apk-tools, it compares an invalid version token by token up to
// the first invalid token and orders the invalid remainder before any
// valid continuation. Callers that must not guess (the matcher) check
// [Valid] first.
package apkversion

// Result bits, as apk-tools' APK_VERSION_* masks; an operator is a set of
// them.
const (
	Equal   = 1
	Less    = 2
	Greater = 4
	Fuzzy   = 8 // "~": equal if the right-hand version is a prefix
)

// Valid reports whether v is a well-formed apk version
// (apk_version_validate).
func Valid(v string) bool {
	sc := newScanner(v)
	for sc.t.typ < tokEnd {
		sc.next()
	}
	return sc.t.typ == tokEnd
}

// Compare returns -1, 0 or +1 as a is older than, equal to or newer than
// b (apk_version_compare).
func Compare(a, b string) int {
	switch compare(a, b, false) {
	case Less:
		return -1
	case Greater:
		return 1
	}
	return 0
}

// compare is apk_version_compare_fuzzy; it returns Less, Equal or
// Greater. With fuzzy, a equals b when b is a token prefix of a.
func compare(a, b string, fuzzy bool) int {
	sa, sb := newScanner(a), newScanner(b)
	for sa.t.typ == sb.t.typ && sa.t.typ < tokEnd {
		switch cmpTokens(&sa.t, &sb.t) {
		case -1:
			return Less
		case 1:
			return Greater
		}
		sa.next()
		sb.next()
	}
	ta, tb := &sa.t, &sb.t
	switch {
	case ta.typ == tb.typ: // both ended, or both invalid at the same place
		return Equal
	case tb.typ == tokEnd && fuzzy:
		return Equal
	// Equal so far: the version with more tokens is newer, unless what
	// follows is a pre-release suffix ("1.0_rc1" < "1.0").
	case ta.typ == tokSuffix && ta.suffix < suffixNone:
		return Less
	case tb.typ == tokSuffix && tb.suffix < suffixNone:
		return Greater
	case ta.typ > tb.typ:
		return Less
	case tb.typ > ta.typ:
		return Greater
	}
	return Equal
}

// ParseOp parses an operator ("<", "<=", "=", ">=", ">", "~", "<~",
// ">~") into a result mask; 0 if it isn't one (apk_version_result_mask).
func ParseOp(op string) int {
	r := 0
	for i := 0; i < len(op); i++ {
		switch op[i] {
		case '<':
			r |= Less
		case '>':
			r |= Greater
		case '=':
			r |= Equal
		case '~':
			r |= Fuzzy | Equal
		default:
			return 0
		}
	}
	return r
}

// Match reports whether "a op b" holds, op being a ParseOp mask
// (apk_version_match, without dependency conflicts).
func Match(a string, op int, b string) bool {
	if op&(Equal|Less|Greater) == Equal|Less|Greater {
		return true
	}
	return compare(a, b, op&Fuzzy != 0)&op != 0
}
