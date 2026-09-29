package npmversion

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// TestNodeSemverFixtures runs node-semver's comparison and equality
// fixtures (testdata/node-semver.txt) both ways round.
func TestNodeSemverFixtures(t *testing.T) {
	f, err := os.Open("testdata/node-semver.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|") // "", a, " op ", b, ""
		if len(parts) != 5 {
			t.Fatalf("malformed %q", line)
		}
		a, op, b := parts[1], strings.TrimSpace(parts[2]), parts[3]
		want := map[string]int{">": 1, "=": 0}[op]
		got, err := CompareStrings(a, b)
		if err != nil {
			t.Errorf("%q vs %q: %v", a, b, err)
			continue
		}
		back, _ := CompareStrings(b, a)
		if got != want || back != -want {
			t.Errorf("Compare(%q, %q) = %d (reverse %d), want %d", a, b, got, back, want)
		}
		n++
	}
	if n < 60 {
		t.Fatalf("only %d vectors read", n)
	}
}

// node-semver test/fixtures/invalid-versions.js (strings only), plus
// forms npm rejects that other semver dialects accept.
func TestInvalid(t *testing.T) {
	for _, v := range []string{
		strings.Repeat("1", 256) + ".0.0",                                         // too long
		"90071992547409910.0.0", "0.90071992547409910.0", "0.0.90071992547409910", // too big
		"hello, world", "xyz",
		"", "1", "1.2", "1.2.3.4", "1.2.3-", "1.2.3+", "1.2.3-a..b", "1.2.3-a_b", "0", "*",
	} {
		if Valid(v) {
			t.Errorf("Valid(%q) = true", v)
		}
	}
}

// Versions and orderings seen in npm packages and the OSV npm feed.
func TestCompareNpm(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"4.17.20", "4.17.21", -1},
		{"4.17.21", "4.17.21", 0},
		{"10.0.0", "9.99.99", 1},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1},
		{"1.0.0-rc.1", "1.0.0", -1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-0", "1.0.0-alpha", -1},
		{"2.0.0+build.1", "2.0.0", 0},
		{"v1.2.3", "1.2.3", 0},
		{"1.2.3beta", "1.2.3-beta", 0}, // loose: prerelease without "-"
		{"1.2.3-9007199254740993", "1.2.3-9007199254740992", 1},
		{"1.2.3-010", "1.2.3-9", 1}, // numeric, leading zeros ignored
	}
	for _, c := range cases {
		got, err := CompareStrings(c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("Compare(%q, %q) = %d, %v; want %d", c.a, c.b, got, err, c.want)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"1.2.3", "v1.2.3-a.1+b", " = 1.2.3", "1.2.3beta", "x"} {
		f.Add(s, "1.0.0")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		c1, e1 := CompareStrings(a, b)
		c2, e2 := CompareStrings(b, a)
		if (e1 == nil) != (e2 == nil) || c1 != -c2 {
			t.Fatalf("asymmetric: %q %q: %d %v / %d %v", a, b, c1, e1, c2, e2)
		}
	})
}
