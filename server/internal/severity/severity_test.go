package severity

import (
	"math"
	"slices"
	"testing"
)

func f(x float64) *float64 { return &x }

func TestParsePriority(t *testing.T) {
	cases := map[string]Priority{
		// Debian urgency.
		"unimportant":      PriorityNegligible,
		"low":              PriorityLow,
		"medium":           PriorityMedium,
		"high":             PriorityHigh,
		"critical":         PriorityCritical,
		"not yet assigned": PriorityUnknown,
		"not_yet_assigned": PriorityUnknown,
		"low**":            PriorityLow,
		"medium*":          PriorityMedium,
		"end-of-life":      PriorityUnknown,
		// Ubuntu priority.
		"negligible": PriorityNegligible,
		"untriaged":  PriorityUnknown,
		// Normalization and junk.
		"  High ":  PriorityHigh,
		"CRITICAL": PriorityCritical,
		"":         PriorityUnknown,
		"unknown":  PriorityUnknown,
		"severe":   PriorityUnknown,
	}
	for in, want := range cases {
		if got := ParsePriority(in); got != want {
			t.Errorf("ParsePriority(%q) = %v, want %v", in, got, want)
		}
	}
	for p := PriorityUnknown; p <= PriorityCritical; p++ {
		if got := ParsePriority(p.String()); got != p {
			t.Errorf("ParsePriority(%v.String()) = %v", p, got)
		}
	}
}

func TestBucketRules(t *testing.T) {
	cases := []struct {
		name string
		in   Input
		want Bucket
	}{
		// Distro priority alone.
		{"critical", Input{DistroPriority: PriorityCritical}, BucketCritical},
		{"high", Input{DistroPriority: PriorityHigh}, BucketHigh},
		{"medium", Input{DistroPriority: PriorityMedium}, BucketMedium},
		{"low", Input{DistroPriority: PriorityLow}, BucketLow},
		{"negligible", Input{DistroPriority: PriorityNegligible}, BucketNegligible},
		{"untriaged", Input{DistroPriority: PriorityUnknown}, BucketUnknown},

		// KEV always wins, even over negligible and without a fix.
		{"kev low", Input{KEV: true, DistroPriority: PriorityLow}, BucketCritical},
		{"kev negligible", Input{KEV: true, DistroPriority: PriorityNegligible}, BucketCritical},
		{"kev untriaged no fix", Input{KEV: true}, BucketCritical},

		// EPSS escalates, at the named thresholds.
		{"epss critical", Input{EPSS: f(EPSSCritical), DistroPriority: PriorityLow}, BucketCritical},
		{"epss just below critical", Input{EPSS: f(0.4999), DistroPriority: PriorityLow}, BucketHigh},
		{"epss high", Input{EPSS: f(EPSSHigh), DistroPriority: PriorityLow}, BucketHigh},
		{"epss medium", Input{EPSS: f(EPSSMedium), DistroPriority: PriorityLow}, BucketMedium},
		{"epss below medium", Input{EPSS: f(0.0099), DistroPriority: PriorityLow}, BucketLow},
		{"epss escalates untriaged", Input{EPSS: f(0.2)}, BucketHigh},
		{"epss medium escalates untriaged", Input{EPSS: f(0.02)}, BucketMedium},
		// ...but never lowers.
		{"epss low keeps critical", Input{EPSS: f(0.0001), DistroPriority: PriorityCritical}, BucketCritical},
		{"epss medium keeps high", Input{EPSS: f(0.05), DistroPriority: PriorityHigh}, BucketHigh},
		// ...and does not override a negligible triage.
		{"epss vs negligible", Input{EPSS: f(0.9), DistroPriority: PriorityNegligible}, BucketNegligible},

		// CVSS never sets the bucket.
		{"cvss 9.8 low", Input{CVSS: f(9.8), DistroPriority: PriorityLow}, BucketLow},
		{"cvss 9.8 untriaged", Input{CVSS: f(9.8)}, BucketUnknown},
		{"cvss 9.8 negligible", Input{CVSS: f(9.8), DistroPriority: PriorityNegligible}, BucketNegligible},

		// Fix availability never changes the bucket.
		{"high no fix", Input{DistroPriority: PriorityHigh, FixAvailable: false}, BucketHigh},
		{"high fix", Input{DistroPriority: PriorityHigh, FixAvailable: true}, BucketHigh},

		// Garbage numbers.
		{"epss NaN", Input{EPSS: f(math.NaN()), DistroPriority: PriorityLow}, BucketLow},
		{"epss >1", Input{EPSS: f(7), DistroPriority: PriorityLow}, BucketCritical},
	}
	for _, tc := range cases {
		if got := Assess(tc.in).Bucket; got != tc.want {
			t.Errorf("%s: bucket = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestBucketOrderAndNames(t *testing.T) {
	want := []string{"negligible", "low", "unknown", "medium", "high", "critical"}
	for i, b := range []Bucket{BucketNegligible, BucketLow, BucketUnknown, BucketMedium, BucketHigh, BucketCritical} {
		if b.String() != want[i] {
			t.Errorf("%d: %q, want %q", b, b.String(), want[i])
		}
		if i > 0 && b <= Bucket(i) {
			t.Errorf("bucket %v not above its predecessor", b)
		}
	}
}

// TestOrdering lists findings from most to least urgent; each adjacent pair
// exercises one rule. Sorting any permutation must reproduce this order.
func TestOrdering(t *testing.T) {
	ordered := []struct {
		name string
		in   Input
	}{
		// Critical bucket: KEV first, even unfixed and distro-low.
		{"kev, high, fix", Input{KEV: true, DistroPriority: PriorityHigh, FixAvailable: true}},
		{"kev, high, no fix", Input{KEV: true, DistroPriority: PriorityHigh}},
		{"kev, low, fix", Input{KEV: true, DistroPriority: PriorityLow, FixAvailable: true}},
		// Then EPSS band beats distro priority inside the bucket.
		{"epss 0.6, low", Input{EPSS: f(0.6), DistroPriority: PriorityLow, FixAvailable: true}},
		{"epss 0.2, critical", Input{EPSS: f(0.2), DistroPriority: PriorityCritical, FixAvailable: true}},
		{"critical, fix, epss 0.009", Input{EPSS: f(0.009), DistroPriority: PriorityCritical, FixAvailable: true}},
		// Fix availability before raw EPSS.
		{"critical, fix, epss 0.001", Input{EPSS: f(0.001), DistroPriority: PriorityCritical, FixAvailable: true}},
		{"critical, no fix, epss 0.009", Input{EPSS: f(0.009), DistroPriority: PriorityCritical}},
		// High bucket.
		{"epss 0.1, medium", Input{EPSS: f(0.1), DistroPriority: PriorityMedium, FixAvailable: true}},
		{"high, fix, cvss 9.8", Input{DistroPriority: PriorityHigh, FixAvailable: true, CVSS: f(9.8)}},
		// CVSS as the final tiebreaker; absent below 0.0.
		{"high, fix, cvss 7.5", Input{DistroPriority: PriorityHigh, FixAvailable: true, CVSS: f(7.5)}},
		{"high, fix, cvss 0", Input{DistroPriority: PriorityHigh, FixAvailable: true, CVSS: f(0)}},
		{"high, fix, no cvss", Input{DistroPriority: PriorityHigh, FixAvailable: true}},
		{"high, no fix, cvss 10", Input{DistroPriority: PriorityHigh, CVSS: f(10)}},
		// Medium bucket.
		{"medium, fix", Input{DistroPriority: PriorityMedium, FixAvailable: true}},
		{"medium, no fix", Input{DistroPriority: PriorityMedium}},
		// Unknown bucket sits between medium and low, CVSS inside it.
		{"untriaged, no fix, cvss 9.8", Input{CVSS: f(9.8)}},
		{"untriaged, no fix, cvss 5", Input{CVSS: f(5)}},
		// Low bucket: untriaged never sinks below it.
		{"low, fix, cvss 9.8", Input{DistroPriority: PriorityLow, FixAvailable: true, CVSS: f(9.8)}},
		{"low, no fix", Input{DistroPriority: PriorityLow}},
		// Negligible bucket, even with a high EPSS.
		{"negligible, epss 0.9", Input{DistroPriority: PriorityNegligible, EPSS: f(0.9)}},
		{"negligible, fix", Input{DistroPriority: PriorityNegligible, FixAvailable: true}},
		{"negligible, no fix", Input{DistroPriority: PriorityNegligible}},
	}

	for i := 1; i < len(ordered); i++ {
		a, b := ordered[i-1], ordered[i]
		if c := Compare(a.in, b.in); c >= 0 {
			t.Errorf("%q should rank above %q (Compare = %d, keys %d vs %d)",
				a.name, b.name, c, Assess(a.in).Key, Assess(b.in).Key)
		}
		if Assess(a.in).Bucket < Assess(b.in).Bucket {
			t.Errorf("list order contradicts buckets: %q (%v) above %q (%v)",
				a.name, Assess(a.in).Bucket, b.name, Assess(b.in).Bucket)
		}
	}

	ins := make([]Input, len(ordered))
	for i, o := range ordered {
		ins[i] = o.in
	}
	shuffled := slices.Clone(ins)
	slices.Reverse(shuffled)
	shuffled[0], shuffled[len(shuffled)/2] = shuffled[len(shuffled)/2], shuffled[0]
	slices.SortStableFunc(shuffled, Compare)
	for i := range ins {
		if Assess(shuffled[i]).Key != Assess(ins[i]).Key {
			t.Fatalf("sort mismatch at %d: got %+v, want %q", i, shuffled[i], ordered[i].name)
		}
	}
}

func TestTiesAndKeyProperties(t *testing.T) {
	a := Input{DistroPriority: PriorityHigh, EPSS: f(0.02), CVSS: f(7.5), FixAvailable: true}
	b := a
	b.EPSS, b.CVSS = f(0.02), f(7.5) // distinct pointers, same values
	if Compare(a, b) != 0 {
		t.Error("identical signals must tie")
	}
	// Absent EPSS ties with EPSS 0 (both mean "no evidence").
	c, d := Input{DistroPriority: PriorityLow}, Input{DistroPriority: PriorityLow, EPSS: f(0)}
	if Compare(c, d) != 0 {
		t.Error("absent EPSS should tie with EPSS 0")
	}
	// CVSS differences below the 0.1 resolution tie.
	if Compare(Input{CVSS: f(7.51)}, Input{CVSS: f(7.49)}) != 0 {
		t.Error("CVSS 7.51 vs 7.49 should tie at 0.1 resolution")
	}
	// Keys are non-negative and fit comfortably in a bigint.
	hi := Assess(Input{KEV: true, EPSS: f(1), DistroPriority: PriorityCritical, CVSS: f(10), FixAvailable: true}).Key
	lo := Assess(Input{DistroPriority: PriorityNegligible}).Key
	if lo <= 0 || hi >= 1<<40 {
		t.Errorf("key range [%d, %d] unexpected", lo, hi)
	}
	// Out-of-range and NaN inputs are clamped, never overflow neighbours.
	weird := Assess(Input{DistroPriority: PriorityLow, EPSS: f(-3), CVSS: f(99)}).Key
	sane := Assess(Input{DistroPriority: PriorityLow, CVSS: f(10)}).Key
	if weird != sane {
		t.Errorf("clamping: %d vs %d", weird, sane)
	}
	if Assess(Input{DistroPriority: PriorityLow, CVSS: f(math.NaN())}).Key !=
		Assess(Input{DistroPriority: PriorityLow}).Key {
		t.Error("NaN CVSS should behave as absent")
	}
}
