// Package cvss computes CVSS v3.x base scores from vector strings, per the
// CVSS v3.1 specification (section 7.1, with the 3.1 Roundup). OSV records
// carry vectors, not scores; cves.cvss_v3_score is derived here.
package cvss

import (
	"fmt"
	"math"
	"strings"
)

var weights = map[string]map[string]float64{
	"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
	"AC": {"L": 0.77, "H": 0.44},
	"UI": {"N": 0.85, "R": 0.62},
	"C":  {"H": 0.56, "L": 0.22, "N": 0},
	"I":  {"H": 0.56, "L": 0.22, "N": 0},
	"A":  {"H": 0.56, "L": 0.22, "N": 0},
}

// V3BaseScore parses "CVSS:3.x/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" and
// returns its base score (0.0-10.0). Temporal/environmental metrics in the
// vector are ignored.
func V3BaseScore(vector string) (float64, error) {
	parts := strings.Split(vector, "/")
	if len(parts) < 9 || !strings.HasPrefix(parts[0], "CVSS:3.") {
		return 0, fmt.Errorf("cvss: not a v3 vector: %q", vector)
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return 0, fmt.Errorf("cvss: bad metric %q", p)
		}
		m[k] = v
	}
	get := func(metric string) (float64, error) {
		w, ok := weights[metric][m[metric]]
		if !ok {
			return 0, fmt.Errorf("cvss: bad or missing %s in %q", metric, vector)
		}
		return w, nil
	}
	scope := m["S"]
	if scope != "U" && scope != "C" {
		return 0, fmt.Errorf("cvss: bad or missing S in %q", vector)
	}
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = map[string]float64{"U": 0.62, "C": 0.68}[scope]
	case "H":
		pr = map[string]float64{"U": 0.27, "C": 0.5}[scope]
	default:
		return 0, fmt.Errorf("cvss: bad or missing PR in %q", vector)
	}
	var w [6]float64
	for i, metric := range []string{"AV", "AC", "UI", "C", "I", "A"} {
		v, err := get(metric)
		if err != nil {
			return 0, err
		}
		w[i] = v
	}
	av, ac, ui, c, i, a := w[0], w[1], w[2], w[3], w[4], w[5]

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	exploitability := 8.22 * av * ac * pr * ui
	if impact <= 0 {
		return 0, nil
	}
	if scope == "U" {
		return roundup(math.Min(impact+exploitability, 10)), nil
	}
	return roundup(math.Min(1.08*(impact+exploitability), 10)), nil
}

// roundup is CVSS v3.1's Roundup: smallest one-decimal number >= x,
// computed on integers to avoid float artifacts.
func roundup(x float64) float64 {
	n := int64(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return float64(n/10000+1) / 10
}
