// Package severity ranks vulnerability findings: one pure function turns
// the signals we hold for a (package, vuln) pair into a coarse display
// Bucket and a totally ordered sort Key. It is the only place ranking
// rules live; SQL and the UI consume its outputs (docs/tasks/phase-1b-vuln-pipeline.md).
//
// # Signal precedence
//
// CISA KEV first, then FIRST EPSS, then the distro's own priority (Debian
// urgency / Ubuntu priority), and CVSS only as a tiebreaker. CVSS alone
// ranks nearly everything "high"; the distro triage says whether the
// vulnerable code is actually shipped and reachable in that release, and
// KEV/EPSS say whether anyone is exploiting it.
//
// # Display bucket
//
// The bucket is the highest level any row below grants (escalations only
// ever raise it):
//
//	Rule                                              Bucket
//	------------------------------------------------  ----------
//	In CISA KEV (any distro priority, fix or not)     critical
//	EPSS >= EPSSCritical (0.50)                       critical   [1]
//	EPSS >= EPSSHigh     (0.10)                       high       [1]
//	EPSS >= EPSSMedium   (0.01)                       medium     [1]
//	Distro priority critical                          critical
//	Distro priority high                              high
//	Distro priority medium                            medium
//	Distro priority low                               low
//	Distro priority negligible (Debian unimportant)   negligible
//	Distro priority unknown (untriaged, not yet       unknown    [2]
//	  assigned, missing, unrecognised)
//
//	[1] EPSS escalation does not apply when the distro triaged the issue as
//	    negligible/unimportant: that is a package-specific judgement (e.g.
//	    the vulnerable code is not built), which a CVE-wide exploit
//	    probability does not override. KEV still does.
//	[2] CVSS never sets the bucket, not even for untriaged issues: it is a
//	    tiebreaker only. Untriaged issues are usually days old and get a
//	    distro priority soon; meanwhile KEV/EPSS still escalate them.
//
// # Sort order
//
// Key compares with plain integer comparison; a higher Key is more urgent.
// Its components, most significant first:
//
//  1. Bucket, ordered critical > high > medium > unknown > low > negligible.
//     The list order therefore never contradicts the badge a row shows.
//     "unknown" sits above low: an untriaged issue must not sink below one
//     the distro has already judged low, and must not jump above medium on
//     CVSS alone.
//  2. KEV.
//  3. EPSS band (>= EPSSCritical, >= EPSSHigh, >= EPSSMedium, below/absent).
//  4. Distro priority (same order as 1).
//  5. Fix availability: fix available > no fix yet.
//  6. Raw EPSS score (0 when absent).
//  7. CVSS base score (absent sorts below 0.0).
//
// Items with equal Keys are equally urgent; callers add a deterministic
// tiebreak (e.g. vuln_key) for stable pagination.
//
// # "No fix yet"
//
// Unfixed findings are never dropped, hidden or demoted out of their
// bucket: a KEV-listed issue with no fix is still critical (you need to
// mitigate it) and still outranks everything that is not KEV. Fix
// availability only breaks ties between findings of equal risk (component
// 5), placing the one you can act on today (upgrade) first. It ranks below
// the risk signals because severity answers "how bad", and "can I fix it"
// is a separate filterable column; it ranks above raw EPSS/CVSS because
// small differences in those scores are noise compared with actionability.
package severity

import (
	"math"
	"strings"
)

// EPSS escalation thresholds (EPSS probability of exploitation activity in
// the next 30 days, 0..1).
const (
	EPSSCritical = 0.50
	EPSSHigh     = 0.10
	EPSSMedium   = 0.01
)

// Priority is a distro severity normalized across Debian urgency and Ubuntu
// priority.
type Priority int

// Priority values. Their numeric values are not an ordering; use Rank.
const (
	PriorityUnknown    Priority = iota // untriaged / not yet assigned / missing
	PriorityNegligible                 // Debian "unimportant", Ubuntu "negligible"
	PriorityLow
	PriorityMedium
	PriorityHigh
	PriorityCritical
)

// ParsePriority maps a Debian urgency (unimportant, low, medium, high,
// critical, "not yet assigned"; tracker-style "low**" uncertainty markers
// are ignored) or Ubuntu priority (negligible, low, medium, high, critical,
// untriaged) to a Priority. Matching is case-insensitive and treats
// spaces, underscores and hyphens alike. Anything unrecognised, including
// "", "unknown" and "end-of-life", is PriorityUnknown.
func ParsePriority(s string) Priority {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimRight(s, "*")
	s = strings.NewReplacer("_", " ", "-", " ").Replace(s)
	switch s {
	case "unimportant", "negligible":
		return PriorityNegligible
	case "low":
		return PriorityLow
	case "medium":
		return PriorityMedium
	case "high":
		return PriorityHigh
	case "critical":
		return PriorityCritical
	default: // "not yet assigned", "untriaged", "unknown", "", ...
		return PriorityUnknown
	}
}

// String returns the normalized lowercase name.
func (p Priority) String() string {
	switch p {
	case PriorityNegligible:
		return "negligible"
	case PriorityLow:
		return "low"
	case PriorityMedium:
		return "medium"
	case PriorityHigh:
		return "high"
	case PriorityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Bucket is the coarse display severity.
type Bucket int

// Buckets, declared in sort order (least urgent first), so Bucket values
// compare directly: unknown ranks between low and medium.
const (
	BucketNegligible Bucket = iota + 1
	BucketLow
	BucketUnknown
	BucketMedium
	BucketHigh
	BucketCritical
)

// String returns the bucket's lowercase name.
func (b Bucket) String() string {
	switch b {
	case BucketNegligible:
		return "negligible"
	case BucketLow:
		return "low"
	case BucketMedium:
		return "medium"
	case BucketHigh:
		return "high"
	case BucketCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// bucket maps a distro priority to its bucket.
func (p Priority) bucket() Bucket {
	switch p {
	case PriorityNegligible:
		return BucketNegligible
	case PriorityLow:
		return BucketLow
	case PriorityMedium:
		return BucketMedium
	case PriorityHigh:
		return BucketHigh
	case PriorityCritical:
		return BucketCritical
	default:
		return BucketUnknown
	}
}

// Input is everything ranking may use about one finding. Nil pointers mean
// "no data" (no EPSS row, no CVSS score), which is distinct from 0.
type Input struct {
	KEV            bool     // listed in CISA KEV
	EPSS           *float64 // FIRST EPSS probability, 0..1
	DistroPriority Priority // from the advisory, via ParsePriority
	CVSS           *float64 // CVSS base score, 0..10 (v3 preferred)
	FixAvailable   bool     // a fixed version exists for this release
}

// Key is an order-preserving rank: higher is more urgent. It is a
// non-negative int64 so it can be stored in a Postgres bigint and used in
// ORDER BY. Its encoding may change between releases (recompute stored
// keys when it does); only its order is meaningful.
type Key int64

// Result is the output of Assess.
type Result struct {
	Bucket Bucket
	Key    Key
}

// Assess computes the display bucket and sort key for one finding. See the
// package documentation for the rules.
func Assess(in Input) Result {
	b := in.DistroPriority.bucket()
	band := epssBand(in.EPSS)
	if in.DistroPriority != PriorityNegligible {
		b = max(b, bandBucket[band])
	}
	if in.KEV {
		b = BucketCritical
	}
	return Result{Bucket: b, Key: key(in, b, band)}
}

// Compare orders findings most urgent first, for slices.SortFunc: it is
// negative when a is more urgent than b.
func Compare(a, b Input) int {
	ka, kb := Assess(a).Key, Assess(b).Key
	switch {
	case ka > kb:
		return -1
	case ka < kb:
		return 1
	}
	return 0
}

// epssBand is 0 (absent or < EPSSMedium) .. 3 (>= EPSSCritical).
func epssBand(epss *float64) int {
	switch e := value(epss); {
	case e >= EPSSCritical:
		return 3
	case e >= EPSSHigh:
		return 2
	case e >= EPSSMedium:
		return 1
	}
	return 0
}

var bandBucket = [...]Bucket{0, BucketMedium, BucketHigh, BucketCritical}

// Key layout (bit widths): bucket 3 | kev 1 | epss band 2 | priority 3 |
// fix 1 | epss score 20 | cvss 7 = 37 bits.
const (
	cvssBits = 7  // 0 = absent, else round(score*10)+1 <= 101
	epssBits = 20 // round(score*1e6) <= 1_000_000 < 2^20
)

func key(in Input, b Bucket, band int) Key {
	k := int64(b)
	k = k<<1 | boolBit(in.KEV)
	k = k<<2 | int64(band)
	k = k<<3 | int64(in.DistroPriority.bucket()) // same order as buckets
	k = k<<1 | boolBit(in.FixAvailable)
	k = k<<epssBits | int64(math.Round(clamp(value(in.EPSS), 0, 1)*1e6))
	var cvss int64
	if in.CVSS != nil && !math.IsNaN(*in.CVSS) {
		cvss = int64(math.Round(clamp(*in.CVSS, 0, 10)*10)) + 1
	}
	k = k<<cvssBits | cvss
	return Key(k)
}

func value(p *float64) float64 {
	if p == nil || math.IsNaN(*p) {
		return 0
	}
	return *p
}

func clamp(x, lo, hi float64) float64 { return math.Min(math.Max(x, lo), hi) }

func boolBit(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
