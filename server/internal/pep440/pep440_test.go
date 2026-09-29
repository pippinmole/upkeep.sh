package pep440

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// vectors reads testdata/packaging.txt: pypa/packaging's own tests.
func vectors(t *testing.T) (order, invalid []string, normalized [][2]string) {
	t.Helper()
	f, err := os.Open("testdata/packaging.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	section := ""
	str := func(s string) string {
		var v string
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			t.Fatalf("bad line %q: %v", s, err)
		}
		return v
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "["):
			section = line
		case section == "[order]":
			order = append(order, str(line))
		case section == "[invalid]":
			invalid = append(invalid, str(line))
		case section == "[normalized]":
			a, b, _ := strings.Cut(line, "\t")
			normalized = append(normalized, [2]string{str(a), str(b)})
		}
	}
	if len(order) < 90 || len(invalid) < 15 || len(normalized) < 100 {
		t.Fatalf("vectors: %d order, %d invalid, %d normalized", len(order), len(invalid), len(normalized))
	}
	return order, invalid, normalized
}

// packaging's VERSIONS: every pair compares as the list orders it.
func TestPackagingOrder(t *testing.T) {
	order, _, _ := vectors(t)
	for i, a := range order {
		for j, b := range order {
			got, err := CompareStrings(a, b)
			if err != nil {
				t.Fatalf("%q vs %q: %v", a, b, err)
			}
			want := cmpInt(i, j)
			// The list holds no two equal versions.
			if got != want {
				t.Errorf("Compare(%q, %q) = %d, want %d", a, b, got, want)
			}
		}
	}
}

func TestPackagingInvalid(t *testing.T) {
	_, invalid, _ := vectors(t)
	for _, v := range invalid {
		if Valid(v) {
			t.Errorf("Valid(%q) = true", v)
		}
	}
	for _, v := range []string{"", "1.0-", "1.2.3.post.dev.x", "latest", "1.0.0_rc1+"} {
		if Valid(v) {
			t.Errorf("Valid(%q) = true", v)
		}
	}
}

func TestPackagingNormalized(t *testing.T) {
	_, _, normalized := vectors(t)
	for _, n := range normalized {
		v, err := Parse(n[0])
		if err != nil {
			t.Errorf("Parse(%q): %v", n[0], err)
			continue
		}
		if v.String() != n[1] {
			t.Errorf("Parse(%q) = %s, want %s", n[0], v, n[1])
		}
		if c, _ := CompareStrings(n[0], n[1]); c != 0 {
			t.Errorf("Compare(%q, %q) = %d, want 0", n[0], n[1], c)
		}
	}
}

// Orderings that matter for PyPI advisories.
func TestComparePyPI(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.31.0", "2.32.0", -1},
		{"1.0", "1.0.0", 0}, // trailing zeros
		{"1.0.post1", "1.0", 1},
		{"1.0rc1", "1.0", -1},
		{"1.0.dev0", "1.0a1", -1},
		{"1.0a1.dev1", "1.0a1", -1},
		{"1!0.1", "2.0", 1}, // epoch
		{"1.0+local", "1.0", 1},
		{"4.2.10", "4.2.9", 1},
		{"0.10", "0.9", 1},
		{"2023.10.1", "2023.9.30", 1},
		{"6.3.2", "6.3.2", 0},
	}
	for _, c := range cases {
		got, err := CompareStrings(c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("Compare(%q, %q) = %d, %v; want %d", c.a, c.b, got, err, c.want)
		}
	}
}

func FuzzCompare(f *testing.F) {
	for _, s := range []string{"1.0", "1!2.0a1.post2.dev3+abc.1", "v1.0-rc1", "x"} {
		f.Add(s, "1.0")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		c1, e1 := CompareStrings(a, b)
		c2, e2 := CompareStrings(b, a)
		if (e1 == nil) != (e2 == nil) || c1 != -c2 {
			t.Fatalf("asymmetric: %q %q: %d %v / %d %v", a, b, c1, e1, c2, e2)
		}
		if e1 == nil {
			va, _ := Parse(a)
			if c, err := CompareStrings(va.String(), a); err != nil || c != 0 {
				t.Fatalf("normal form %q of %q: %d %v", va.String(), a, c, err)
			}
		}
	})
}
