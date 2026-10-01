package goversion

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// x/mod's own table, run as its TestIsValid and TestCompare do.
func TestXModSemverTable(t *testing.T) {
	f, err := os.Open("testdata/x-mod-semver.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	type row struct{ in, out string }
	var rows []row
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		in, out, _ := strings.Cut(line, "\t")
		rows = append(rows, row{in, out})
	}
	if len(rows) < 30 {
		t.Fatalf("only %d rows", len(rows))
	}
	for i, ri := range rows {
		if Valid(ri.in) != (ri.out != "") {
			t.Errorf("Valid(%q) = %v", ri.in, ri.out == "")
		}
		for j, rj := range rows {
			if ri.out == "" || rj.out == "" {
				continue
			}
			want := 0
			if ri.out != rj.out {
				want = map[bool]int{true: -1, false: 1}[i < j]
			}
			if got, err := Compare(ri.in, rj.in); err != nil || got != want {
				t.Errorf("Compare(%q, %q) = %d, %v; want %d", ri.in, rj.in, got, err, want)
			}
		}
	}
}

// The spellings that meet in Go matching (SBOMs, OSV ranges, Go releases).
func TestCompareGo(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.1.0", "v0.1.0", 0},                               // SBOM / OSV without "v"
		{"v0.17.0", "0.23.0", -1},                            // golang.org/x/net
		{"go1.22.3", "1.22.3", 0},                            // stdlib as Syft writes it
		{"1.24.6", "1.24.7", -1},                             // stdlib, OSV range
		{"go1.21rc2", "1.21.0-rc.2", 0},                      // Go release candidate
		{"1.21beta1", "1.21.0-rc.1", -1},                     // beta < rc
		{"go1.21rc2", "1.21.0", -1},                          // rc < release
		{"go1.20", "1.20.0", 0},                              // "go1.20" is 1.20.0
		{"v2.0.0+incompatible", "2.0.0", 0},                  // build metadata ignored
		{"v0.0.0-20210101120000-abcdef123456", "v0.0.1", -1}, // pseudo-version
		{"v0.0.0-20210101120000-abcdef123456", "v0.0.0-20220101120000-abcdef123456", -1},
		{"v1.2.4-0.20210101120000-abcdef123456", "v1.2.3", 1}, // pseudo after v1.2.3
		{"v1.2.4-0.20210101120000-abcdef123456", "v1.2.4", -1},
	}
	for _, c := range cases {
		got, err := Compare(c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("Compare(%q, %q) = %d, %v; want %d", c.a, c.b, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "latest", "v1.2.3.4", "master", "1.2.3-", "gox1.2"} {
		if Valid(bad) {
			t.Errorf("Valid(%q) = true", bad)
		}
	}
}
