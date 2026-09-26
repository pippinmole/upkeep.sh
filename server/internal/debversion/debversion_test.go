package debversion

import (
	"bufio"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Parse vectors ported from dpkg's lib/dpkg/t/t-version.c
// (test_version_parse).
func TestParseDpkgVectors(t *testing.T) {
	ok := []struct {
		in   string
		want Version
	}{
		{"0", Version{0, "0", ""}},
		{"0:0", Version{0, "0", ""}},
		{"0:0-0", Version{0, "0", "0"}},
		{"0:0.0-0.0", Version{0, "0.0", "0.0"}},
		// Epochs.
		{"1:0", Version{1, "0", ""}},
		{"5:1", Version{5, "1", ""}},
		// Multiple hyphens: the revision starts after the last one.
		{"0:0-0-0", Version{0, "0-0", "0"}},
		{"0:0-0-0-0", Version{0, "0-0-0", "0"}},
		// Multiple colons: the epoch ends at the first one.
		{"0:0:0-0", Version{0, "0:0", "0"}},
		{"0:0:0:0-0", Version{0, "0:0:0", "0"}},
		// Multiple hyphens and colons.
		{"0:0:0-0-0", Version{0, "0:0-0", "0"}},
		{"0:0-0:0-0", Version{0, "0-0:0", "0"}},
		// Valid characters in upstream version and revision.
		{"0:09azAZ.-+~:-0", Version{0, "09azAZ.-+~:", "0"}},
		{"0:0-azAZ09.+~", Version{0, "0", "azAZ09.+~"}},
		// Leading and trailing blanks.
		{"  \t0:0-1", Version{0, "0", "1"}},
		{"0:0-1\t  ", Version{0, "0", "1"}},
		{"\t  0:0-1  \t", Version{0, "0", "1"}},
		// Accepted by dpkg's strtol-based epoch parsing.
		{"+1:0", Version{1, "0", ""}},
		{"-0:0", Version{0, "0", ""}},
		{"2147483647:0", Version{2147483647, "0", ""}},
	}
	for _, tc := range ok {
		got, err := ParseStrict(tc.in)
		if err != nil {
			t.Errorf("ParseStrict(%q): unexpected error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseStrict(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}

	errs := []string{
		"", "  ", // empty
		"0:",                           // empty upstream after epoch
		":1.0",                         // empty epoch
		"1.0-",                         // empty revision
		"0:0-",                         // empty revision after epoch
		"0:0 0-1",                      // embedded space
		"-1:0-1",                       // negative epoch
		"999999999999999999999999:0-1", // huge epoch
		"2147483648:0",                 // > INT_MAX
		"a:0-0", "A:0-0", "1a:0",       // non-numeric epoch
		"-0", "0:-0", // empty upstream
	}
	for _, in := range errs {
		_, err := Parse(in)
		var pe *ParseError
		if !errors.As(err, &pe) || pe.Warning || !errors.Is(err, ErrInvalid) {
			t.Errorf("Parse(%q): want hard *ParseError, got %v", in, err)
		}
	}

	warns := []string{
		"0:abc3-0", // upstream does not start with a digit
		"0:0-0:0",  // ':' is invalid in a revision
	}
	for _, c := range "!#@$%&/|\\<>()[]{};,_=*^'" {
		warns = append(warns, "0:0"+string(c)+"-0", "0:0-"+string(c))
	}
	warns = append(warns, "1.0é-1", "1.0-1\x00")
	for _, in := range warns {
		if _, err := Parse(in); err != nil {
			t.Errorf("Parse(%q): warning-class version must be accepted, got %v", in, err)
		}
		_, err := ParseStrict(in)
		var pe *ParseError
		if !errors.As(err, &pe) || !pe.Warning {
			t.Errorf("ParseStrict(%q): want warning *ParseError, got %v", in, err)
		}
	}
}

// Compare vectors ported from dpkg's lib/dpkg/t/t-version.c
// (test_version_compare), which work on already-split versions.
func TestCompareDpkgObjects(t *testing.T) {
	cases := []struct {
		a, b Version
		want int
	}{
		{Version{0, "0", "0"}, Version{0, "0", "0"}, 0},
		{Version{0, "0", "00"}, Version{0, "00", "0"}, 0},
		{Version{1, "2", "3"}, Version{1, "2", "3"}, 0},
		{Version{0, "0", "0"}, Version{1, "0", "0"}, -1},
		{Version{0, "0", "0"}, Version{0, "a", "0"}, -1},
		{Version{0, "0", "0"}, Version{0, "0", "a"}, -1},
		{Version{1, "0", "0"}, Version{0, "0", "0"}, 1},
		{Version{0, "a", "0"}, Version{0, "0", "0"}, 1},
		{Version{0, "0", "a"}, Version{0, "0", "0"}, 1},
		{Version{0, "a", "0"}, Version{0, "b", "0"}, -1},
		{Version{0, "0", "a"}, Version{0, "0", "b"}, -1},
	}
	for _, tc := range cases {
		if got := Compare(tc.a, tc.b); got != tc.want {
			t.Errorf("Compare(%+v, %+v) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// compareCases are (a, b, sign of a-b). The first block is ported from
// dpkg's scripts/t/Dpkg_Version.t; the rest are real backport/security
// suffixes and edge cases. All of them are also in
// testdata/dpkg_compare_vectors.txt, i.e. confirmed against real dpkg.
var compareCases = []struct {
	a, b string
	want int
}{
	// dpkg scripts/t/Dpkg_Version.t
	{"1.0-1", "2.0-2", -1},
	{"2.2~rc-4", "2.2-1", -1},
	{"2.2-1", "2.2~rc-4", 1},
	{"1.0000-1", "1.0-1", 0},
	{"1", "0:1", 0},
	{"0", "0:0-0", 0},
	{"2:2.5", "1:7.5", 1},
	{"1:0foo", "0foo", 1},
	{"0:0foo", "0foo", 0},
	{"0foo", "0foo", 0},
	{"0foo-0", "0foo", 0},
	{"0foo", "0foo-0", 0},
	{"0foo", "0fo", 1},
	{"0foo-0", "0foo+", -1},
	{"0foo~1", "0foo", -1},
	{"0foo~foo+Bar", "0foo~foo+bar", -1},
	{"0foo~~", "0foo~", -1},
	{"1~", "1", -1},
	{"12345+that-really-is-some-ver-0", "12345+that-really-is-some-ver-10", -1},
	{"0foo-0", "0foo-01", -1},
	{"0foo.bar", "0foobar", 1},
	{"0foo.bar", "0foo1bar", 1},
	{"0foo.bar", "0foo0bar", 1},
	{"0foo1bar-1", "0foobar-1", -1},
	{"0foo2.0", "0foo2", 1},
	{"0foo2.0.0", "0foo2.10.0", -1},
	{"0foo2.0", "0foo2.0.0", -1},
	{"0foo2.0", "0foo2.10", -1},
	{"0foo2.1", "0foo2.10", -1},
	{"1.09", "1.9", 0},
	{"1.0.8+nmu1", "1.0.8", 1},
	{"3.11", "3.10+nmu1", 1},
	{"0.9j-20080306-4", "0.9i-20070324-2", 1},
	{"1.2.0~b7-1", "1.2.0~b6-1", 1},
	{"1.011-1", "1.06-2", 1},
	{"0.0.9+dfsg1-1", "0.0.8+dfsg1-3", 1},
	{"4.6.99+svn6582-1", "4.6.99+svn6496-1", 1},
	{"53", "52", 1},
	{"0.9.9~pre122-1", "0.9.9~pre111-1", 1},
	{"2:2.3.2-2+lenny2", "2:2.3.2-2", 1},
	{"1:3.8.1-1", "3.8.GA-1", 1},
	{"1.0.1+gpl-1", "1:1.0-1", -1},

	// Plain text ordering gets these wrong.
	{"1.10", "1.9", 1},
	{"1.0~rc1", "1.0", -1},
	{"1.0~rc1", "1.0~rc2", -1},
	{"1.0~~", "1.0~", -1},
	{"1:2.0", "3.0", 1},
	{"1.0", "1.0+b1", -1},
	{"1.0-1", "1.0-1+b1", -1},
	{"1.0", "1.0-0", 0},
	{"1.0", "1.0.0", -1},
	{"1.0a", "1.0.", -1}, // letters sort before non-letters
	{"1.0a", "1.0", 1},
	{"1.0+", "1.0a", 1},
	{"1.0~", "1.0", -1},
	{"1.0~", "1.0a", -1},
	{"1.0A", "1.0a", -1},

	// Debian stable/oldstable security and point-release suffixes.
	{"1.1.1n-0+deb11u5", "1.1.1n-0+deb11u4", 1},
	{"1.1.1w-0+deb11u1", "1.1.1n-0+deb11u5", 1},
	{"3.0.11-1~deb12u2", "3.0.11-1", -1},
	{"3.0.11-1~deb12u2", "3.0.11-1~deb12u1", 1},
	{"3.0.14-1~deb12u1", "3.0.11-1~deb12u2", 1},
	{"2.36-9+deb12u4", "2.36-9", 1},
	{"2.36-9+deb12u4", "2.36-9+deb12u10", -1},
	{"7.88.1-10+deb12u5", "7.88.1-10+deb12u12", -1},
	{"1:9.18.24-1~deb12u1", "1:9.18.19-1~deb12u1", 1},
	{"9.2p1-2+deb12u3", "1:9.2p1-2+deb12u3", -1},
	// Backports sort below the stable version they backport.
	{"6.1.0-0~bpo11+1", "6.1.0-1", -1},
	{"6.1.0-1~bpo11+1", "6.1.0-1", -1},
	{"6.1.0-1~bpo11+1", "6.1.0-1~bpo11+2", -1},
	{"2.5-1~bpo12+1", "2.4-1", 1},
	// Ubuntu SRU/security suffixes.
	{"3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.9", 1},
	{"3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1", 1},
	{"2.35-0ubuntu3.8", "2.35-0ubuntu3.10", -1},
	{"1.2.3-1ubuntu0.22.04.1", "1.2.3-1", 1},
	{"1.2.3-1ubuntu0.22.04.1", "1.2.3-1ubuntu1", -1},
	{"1.2.3-1ubuntu0.20.04.2", "1.2.3-1ubuntu0.22.04.1", -1},
	{"2024a-0ubuntu0.22.04", "2024a-0ubuntu0.22.04.1", -1},
	{"5.15.0-105.115", "5.15.0-91.101", 1},
	{"1:9.18.18-0ubuntu0.22.04.2", "1:9.18.18-0ubuntu0.22.04.1", 1},
	// Ubuntu Pro / ESM.
	{"1.2.3-1ubuntu0.1+esm1", "1.2.3-1ubuntu0.1", 1},
	{"1.2.3-1ubuntu0.1+esm1", "1.2.3-1ubuntu0.1+esm2", -1},
	{"1.2.3-1ubuntu0.1+esm1", "1.2.3-1ubuntu0.2", -1},
	{"2.7.18-1~20.04.3+esm1", "2.7.18-1~20.04.3", 1},
	{"1.2.3-1ubuntu0.1~esm1", "1.2.3-1ubuntu0.1", -1},
	// Epochs dominate everything.
	{"1:0", "99999999999999999999", 1},
	{"2:1.0", "1:9.9", 1},
	{"0:1.0", "1.0", 0},
	{"10:1", "9:1", 1},
	// Huge digit runs (no overflow; leading zeros ignored).
	{"1.99999999999999999999999999999", "1.99999999999999999999999999998", 1},
	{"1.100000000000000000000000000000", "1.99999999999999999999999999999", 1},
	{"1.000000000000000000000000000001", "1.1", 0},
	{"18446744073709551616", "18446744073709551615", 1},
	{"1-18446744073709551616", "1-18446744073709551617", -1},
	{"00000", "0", 0},
}

func TestCompareCases(t *testing.T) {
	for _, tc := range compareCases {
		got, err := CompareStrings(tc.a, tc.b)
		if err != nil {
			t.Errorf("CompareStrings(%q, %q): %v", tc.a, tc.b, err)
			continue
		}
		if got != tc.want {
			t.Errorf("CompareStrings(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		// Antisymmetry on every vector.
		if rev, _ := CompareStrings(tc.b, tc.a); rev != -tc.want {
			t.Errorf("CompareStrings(%q, %q) = %d, want %d", tc.b, tc.a, rev, -tc.want)
		}
	}
}

// TestDpkgVectors replays pairs whose expected result came from running
// `dpkg --compare-versions` (dpkg 1.21.1, amd64) in ubuntu:22.04.
func TestDpkgVectors(t *testing.T) {
	f, err := os.Open("testdata/dpkg_compare_vectors.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			t.Fatalf("bad vector line %q", line)
		}
		a, b := fields[0], fields[1]
		got, err := CompareStrings(a, b)
		if fields[2] == "ERR" {
			if err == nil {
				t.Errorf("CompareStrings(%q, %q): dpkg rejects this, want error", a, b)
			}
			continue
		}
		want, _ := strconv.Atoi(fields[2])
		if err != nil || got != want {
			t.Errorf("CompareStrings(%q, %q) = %d, %v; dpkg says %d", a, b, got, err, want)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n < 500 {
		t.Fatalf("only %d vectors checked", n)
	}
}

func TestCompareStringsError(t *testing.T) {
	if _, err := CompareStrings("1.0", ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("want ErrInvalid, got %v", err)
	}
	if _, err := CompareStrings("a:1", "1.0"); !errors.Is(err, ErrInvalid) {
		t.Errorf("want ErrInvalid, got %v", err)
	}
}

func TestStringRoundTrip(t *testing.T) {
	cases := map[string]string{
		"1.0":             "1.0",
		"0:1.0":           "1.0",
		"1:1.0-1":         "1:1.0-1",
		"  1.0-1\t":       "1.0-1",
		"0:1:2-3":         "0:1:2-3", // upstream colon forces the epoch
		"1.0-2-3":         "1.0-2-3",
		"0:0-:":           "0:0-:", // so does a (warning-class) revision colon
		"+1:2":            "1:2",
		"00:1":            "1",
		"1.2.3~bpo11+1-2": "1.2.3~bpo11+1-2",
		"abc":             "abc", // warning class
	}
	for in, want := range cases {
		v := MustParse(in)
		if got := v.String(); got != want {
			t.Errorf("Parse(%q).String() = %q, want %q", in, got, want)
		}
		again, err := Parse(v.String())
		if err != nil || again != v {
			t.Errorf("round trip of %q: got %+v, %v; want %+v", in, again, err, v)
		}
	}
}

func TestMustParsePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("MustParse(\"\") did not panic")
		}
	}()
	MustParse("")
}

func FuzzCompare(f *testing.F) {
	for _, tc := range compareCases {
		f.Add(tc.a, tc.b)
	}
	f.Add("1:~", "~~a0")
	f.Add("1.0\xff-1", "1.0.-1")
	f.Fuzz(func(t *testing.T, a, b string) {
		va, errA := Parse(a)
		vb, errB := Parse(b)
		if errA != nil || errB != nil {
			return
		}
		ab, ba := Compare(va, vb), Compare(vb, va)
		if ab != -ba || ab < -1 || ab > 1 {
			t.Fatalf("not antisymmetric: cmp(%q,%q)=%d cmp(%q,%q)=%d", a, b, ab, b, a, ba)
		}
		if Compare(va, va) != 0 || Compare(vb, vb) != 0 {
			t.Fatalf("not reflexive: %q or %q", a, b)
		}
		// String() round trips to an identical (so equal) version.
		if again, err := Parse(va.String()); err != nil || again != va {
			t.Fatalf("round trip %q -> %q -> %+v, %v", a, va.String(), again, err)
		}
		// Consistency with a third, derived version: appending "~" to the
		// revision/upstream always sorts strictly lower.
		lower := va
		if lower.Revision != "" {
			lower.Revision += "~"
		} else {
			lower.Upstream += "~"
		}
		if Compare(lower, va) != -1 {
			t.Fatalf("%q with trailing ~ does not sort lower", a)
		}
	})
}
