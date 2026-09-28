package apkversion

// Tokenizer: a port of apk-tools src/version.c (token_first, token_next,
// token_cmp). A version is read as a sequence of typed tokens; the order
// of the token types below matters, both for which token may follow which
// and for comparing versions that differ in their next token type.

type tokenType int

const (
	tokInitialDigit tokenType = iota // the leading number
	tokDigit                         // ".N"
	tokLetter                        // one letter right after a number: "1.2a"
	tokSuffix                        // "_alpha", "_p", ...
	tokSuffixNo                      // the number right after a suffix: "_rc2"
	tokCommitHash                    // "~<hex>"
	tokRevisionNo                    // "-rN"
	tokEnd
	tokInvalid
)

// Suffix values, in apk's order: pre-release suffixes sort before a
// version without one (suffixNone), post-release ones after.
const (
	suffixInvalid = iota
	suffixAlpha
	suffixBeta
	suffixPre
	suffixRC
	suffixNone
	suffixCVS
	suffixSVN
	suffixGit
	suffixHg
	suffixP
)

var suffixes = map[string]int{
	"alpha": suffixAlpha, "beta": suffixBeta, "pre": suffixPre, "rc": suffixRC,
	"cvs": suffixCVS, "svn": suffixSVN, "git": suffixGit, "hg": suffixHg, "p": suffixP,
}

type token struct {
	typ    tokenType
	suffix int
	number uint64 // wraps on overflow, as apk_blob_pull_uint does
	value  string // the token's text (digits, letter, suffix word, hash)
}

// scanner walks one version string.
type scanner struct {
	s string // unread rest
	t token
}

func newScanner(v string) *scanner {
	sc := &scanner{s: v}
	sc.t.typ = tokInitialDigit
	sc.digits()
	return sc
}

// digits reads a decimal number; none at all is invalid.
func (sc *scanner) digits() {
	i := 0
	var n uint64
	for i < len(sc.s) && sc.s[i] >= '0' && sc.s[i] <= '9' {
		n = n*10 + uint64(sc.s[i]-'0')
		i++
	}
	sc.t.number, sc.t.value, sc.s = n, sc.s[:i], sc.s[i:]
	if i == 0 {
		sc.t.typ = tokInvalid
	}
}

// span returns the longest prefix of sc.s whose bytes satisfy ok.
func (sc *scanner) span(ok func(byte) bool) string {
	i := 0
	for i < len(sc.s) && ok(sc.s[i]) {
		i++
	}
	v := sc.s[:i]
	sc.s = sc.s[i:]
	return v
}

func isLower(c byte) bool { return c >= 'a' && c <= 'z' }
func isHex(c byte) bool   { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' }

// next advances to the next token, validating that its type may follow
// the current one (token_next).
func (sc *scanner) next() {
	t := &sc.t
	if sc.s == "" {
		t.typ = tokEnd
		return
	}
	switch c := sc.s[0]; {
	case isLower(c):
		if t.typ > tokDigit {
			t.typ = tokInvalid
			return
		}
		t.value, t.typ = sc.s[:1], tokLetter
		sc.s = sc.s[1:]
	case c == '.' || c >= '0' && c <= '9':
		if c == '.' {
			if t.typ > tokDigit {
				t.typ = tokInvalid
				return
			}
			sc.s = sc.s[1:]
		}
		switch t.typ {
		case tokInitialDigit, tokDigit:
			t.typ = tokDigit
		case tokSuffix:
			t.typ = tokSuffixNo
		default:
			t.typ = tokInvalid
			return
		}
		sc.digits()
	case c == '_':
		if t.typ > tokSuffixNo {
			t.typ = tokInvalid
			return
		}
		sc.s = sc.s[1:]
		t.value = sc.span(isLower)
		t.suffix = suffixes[t.value] // "" and unknown words: suffixInvalid
		if t.suffix == suffixInvalid {
			t.typ = tokInvalid
			return
		}
		t.typ = tokSuffix
	case c == '~':
		if t.typ >= tokCommitHash {
			t.typ = tokInvalid
			return
		}
		sc.s = sc.s[1:]
		t.value = sc.span(isHex)
		if t.value == "" {
			t.typ = tokInvalid
			return
		}
		t.typ = tokCommitHash
	case c == '-':
		if t.typ >= tokRevisionNo || len(sc.s) < 2 || sc.s[1] != 'r' {
			t.typ = tokInvalid
			return
		}
		sc.s = sc.s[2:]
		t.typ = tokRevisionNo
		sc.digits()
	default:
		t.typ = tokInvalid
	}
}

// cmpTokens compares two tokens of the same type (token_cmp).
func cmpTokens(a, b *token) int {
	switch a.typ {
	case tokDigit:
		// A leading zero on either side ("1.02" vs "1.1") compares the
		// digits as strings, as the Gentoo version spec does.
		if a.value[0] == '0' || b.value[0] == '0' {
			return blobSort(a.value, b.value)
		}
		return cmpUint(a.number, b.number)
	case tokInitialDigit, tokSuffixNo, tokRevisionNo:
		return cmpUint(a.number, b.number)
	case tokLetter:
		return cmpUint(uint64(a.value[0]), uint64(b.value[0]))
	case tokSuffix:
		return cmpUint(uint64(a.suffix), uint64(b.suffix))
	default: // tokCommitHash
		return blobSort(a.value, b.value)
	}
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

// blobSort is apk_blob_sort: bytewise on the common prefix, then the
// shorter string first.
func blobSort(a, b string) int {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != b[i] {
			return cmpUint(uint64(a[i]), uint64(b[i]))
		}
	}
	return cmpUint(uint64(len(a)), uint64(len(b)))
}
