package apkversion

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// TestApkToolsVectors runs apk-tools' own test list (testdata/version.data),
// interpreted as apk-tools' version_test.c does.
func TestApkToolsVectors(t *testing.T) {
	f, err := os.Open("testdata/version.data")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for line := 0; sc.Scan(); {
		line++
		arg, _, _ := strings.Cut(sc.Text(), "#")
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}
		n++
		var ok bool
		var invert bool
		if v1, rest, found := strings.Cut(arg, " "); found {
			op, v2, found := strings.Cut(rest, " ")
			if !found {
				t.Fatalf("line %d: malformed %q", line, arg)
			}
			op, invert = strings.CutPrefix(op, "!")
			ok = Match(v1, ParseOp(op), v2)
		} else {
			v, inv := strings.CutPrefix(arg, "!")
			invert = inv
			ok = Valid(v)
		}
		if ok == invert {
			t.Errorf("line %d: %q does not hold", line, arg)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n < 700 {
		t.Fatalf("only %d vectors read", n)
	}
}

// Cases seen in Alpine packages and the Alpine OSV feed.
func TestCompareAlpine(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// Revisions.
		{"3.3.2-r0", "3.3.2-r1", -1},
		{"1.2.5-r10", "1.2.5-r9", 1},
		{"1.2.5-r0", "1.2.5-r0", 0},
		// OSV upstream-only bounds ("introduced: 3.0.0", "fixed: 7.51.0")
		// sit below every packaged revision of that version.
		{"3.0.0", "3.0.0-r0", -1},
		{"7.51.0-r0", "7.51.0", 1},
		{"3.0.14-r0", "3.0.15-r0", -1},
		// Numeric, not textual.
		{"3.3.10-r0", "3.3.9-r5", 1},
		{"1.36.1-r29", "1.36.1-r3", 1},
		// Letters and suffixes.
		{"20190514a-r0", "20190514-r0", 1},
		{"20190514a-r0", "20190618-r0", -1},
		{"1.0_rc1-r0", "1.0-r0", -1},
		{"1.0_alpha1", "1.0_beta1", -1},
		{"1.0_p1-r0", "1.0-r5", 1},
		{"1.0_git20240101-r0", "1.0-r0", 1},
		{"1.0_git20240101-r0", "1.0_p1-r0", -1},
		{"2.9.14_git20240101", "2.9.14_git20231201", 1},
		// Leading zeros compare as strings.
		{"8.2.0", "8.2.001", -1},
		{"1.02", "1.1", -1},
		// Commit hashes.
		{"1.0~1234-r1", "1.0~2345-r0", -1},
		// Anything is newer than "0" (secdb's "never affected" marker).
		{"0.1-r0", "0", 1},
		{"0", "0", 0},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := Compare(c.b, c.a); got != -c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestInvalidDoesNotPanic(t *testing.T) {
	for _, v := range []string{
		"", "-", "-r", "_", "~", ".", "a", "1.", "1..2", "1-r", "1-x1",
		"1_", "1_foo", "1~", "1~xyz", "1-r1-r2", "1.0bc", "\x00", "1\x002", "1.2.3 ", "99999999999999999999999",
	} {
		_ = Valid(v)
		for _, w := range []string{"", "1", "1.0-r0", v} {
			_ = Compare(v, w)
			_ = Match(v, ParseOp("<~"), w)
		}
	}
	if Valid("") || Valid("1.0bc") || Valid("1-r") || !Valid("99999999999999999999999") {
		t.Error("validity of edge cases")
	}
}

func FuzzCompare(f *testing.F) {
	for _, s := range []string{"1.0", "1.0-r1", "1.0_rc1", "1.0a", "1.0~abc-r2", "0", "", "1.0bc"} {
		f.Add(s, "1.0-r0")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		ab, ba := Compare(a, b), Compare(b, a)
		if Valid(a) && Valid(b) && ab != -ba {
			t.Errorf("not antisymmetric: %q vs %q: %d, %d", a, b, ab, ba)
		}
		if Compare(a, a) != 0 {
			t.Errorf("%q != itself", a)
		}
	})
}
