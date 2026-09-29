package debversion

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// testdata/dpkg_compare_vectors.txt is a copy of the server's
// (server/internal/debversion/testdata): pairs checked against real
// `dpkg --compare-versions`, so this copy orders exactly like dpkg and
// like the server.
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
		got, err := CompareStrings(fields[0], fields[1])
		if fields[2] == "ERR" {
			if err == nil {
				t.Errorf("CompareStrings(%q, %q): dpkg rejects this, want error", fields[0], fields[1])
			}
			continue
		}
		want, _ := strconv.Atoi(fields[2])
		if err != nil || got != want {
			t.Errorf("CompareStrings(%q, %q) = %d, %v; dpkg says %d", fields[0], fields[1], got, err, want)
		}
		n++
	}
	if n < 500 {
		t.Fatalf("only %d vectors checked", n)
	}
}

func TestKernelVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"6.8.0-45.45", "6.8.0-47.47", -1},
		{"6.11.0-19.19~24.04.1", "6.8.0-47.47", 1},
		{"6.1.76-1", "6.1.69-1", 1},
		{"6.1.0-18.1", "6.1.0-18.1", 0},
	}
	for _, c := range cases {
		if got, err := CompareStrings(c.a, c.b); err != nil || got != c.want {
			t.Errorf("CompareStrings(%q, %q) = %d, %v; want %d", c.a, c.b, got, err, c.want)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, s := range []string{"", " ", "1 2", ":1", "a:1", "-1:1", "1:", "1.0-", "99999999999:1"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q): want error", s)
		}
	}
}
