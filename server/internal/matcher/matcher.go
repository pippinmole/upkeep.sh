// Package matcher decides which vulnerabilities affect one interned package
// version (DOMAIN_MODEL.md §2.5, §2.6). It is pure: the store loads a
// version's advisory_affected rows (same distro, release and source
// package), calls Evaluate, and materializes the result in
// software_vulnerabilities. Versions are compared in Go with the
// ecosystem's Comparator (ecosystems.go: debversion for deb, apkversion
// for apk), never in SQL.
//
// # Keys
//
// Every match is keyed by a vuln_key: a CVE id wherever one is known.
// Per-CVE records (DEBIAN-CVE-*, UBUNTU-CVE-*, ALPINE-CVE-*, CVE-*) key by
// their CVE.
// Notices (DSA, DLA, USN, LSN) are expanded to every CVE they cite, so a
// USN fixing eight CVEs yields eight CVE-keyed matches instead of one
// USN-keyed match that would duplicate the per-CVE ones. A notice citing
// no CVE keys by its own id.
//
// # Which records decide
//
// For one (source package, vuln_key), the per-CVE record is authoritative
// when one exists: notices are derived from the same tracker and can lag
// or disagree (a DSA's fixed version is the first upload; the per-CVE
// record follows regressions and "not affected" triage). Notices then only
// contribute their ids as references (advisory_ids). Only when no per-CVE
// record covers the source do the notices decide.
//
// # The predicate (one advisory_affected row, installed source version v)
//
//	introduced ∈ {"", "0"} or v >= introduced     (else: out of range)
//	fixed set:          v <  fixed  -> affected, fix = fixed
//	                    v >= fixed  -> fixed (the fix is installed)
//	last_affected set:  v <= last   -> affected, no known fix
//	                    v >  last   -> fixed
//	neither:                           affected, no fix (unfixed)
//
// Several rows of one channel (several records, or several ranges of one
// record) combine as: any row saying "fixed" wins (the fix is installed:
// a later notice for the same CVE, e.g. a regression update, must not
// re-open it); otherwise any "affected" row makes the channel affected,
// with the lowest fixed version among its affected rows as the fix.
//
// # Language ecosystems (npm, PyPI, Go)
//
// Language advisories (GHSA-, PYSEC-, GO- records from OSV) are none of
// the above: they are keyed like notices (their CVE aliases, else their
// GHSA or own id; osv.vulnKey), and several of them may describe one CVE
// for one package (a GHSA and a PYSEC, a GHSA and a GO record). Their
// rows are ranges of an upstream package's releases, and one record
// routinely lists several (one per maintained branch: [0, 1.2.3),
// [2.0.0, 2.0.5)), so "v >= fixed" of one range says nothing about the
// others and "any fixed row wins" would hide 2.0.1 above. For these
// ecosystems (the comparator is wrapped in osvRanges) rows combine as the
// OSV schema defines: the version is affected when any row's range
// contains it, across every record citing the key; the fix is the
// lowest fixed version among the rows that contain it. Records that
// disagree therefore both count (the union), as osv-scanner does.
//
// # Channels (Ubuntu Pro / ESM, DOMAIN_MODEL.md Q9)
//
// Rows are either 'standard' (the release's archive) or 'ubuntu-pro'
// (fix, or tracking, only in Ubuntu Pro / ESM):
//
//   - a standard verdict of "not affected" (fixed or out of range) means no
//     match, whatever the Pro rows say;
//   - a Pro verdict of "not affected" also means no match: the host runs
//     an +esm build that contains the fix;
//   - otherwise the version is affected if either channel says so. A
//     standard fix wins; a fix only in the Pro channel is reported with
//     FixChannel "ubuntu-pro" ("fix requires Ubuntu Pro"); no fix in
//     either leaves FixChannel empty.
package matcher

import (
	"cmp"
	"slices"
	"strings"

	"github.com/pippinmole/upkeep.sh/server/internal/osv"
)

// Version is bumped whenever Evaluate, Resolve (kernel mapping) or the
// store's match materialization changes output for the same inputs. The
// worker's matcher_sweep then re-evaluates every software_versions row
// whose matcher_version is lower, in batches.
//
//	1  P1b: deb only (debversion).
//	2  Per-ecosystem comparators: apk versions (image packages, interned
//	   since migration 0014 and evaluated as "not matched" under 1) are
//	   now matched with apkversion. deb results are unchanged; their
//	   re-evaluation only restamps matcher_version.
//	3  Assessed needs a supported release (distro_releases.supported):
//	   packages of an end-of-life or unknown release are "not assessed".
//	   Matches are unchanged (only supported releases' advisories are
//	   imported); the bump re-scores image lists (image_sbom_scores
//	   .not_assessed_count), and version re-evaluation only restamps.
//	4  npm packages are matched (npmversion, OSV range semantics; see
//	   "Language ecosystems"), evaluated as "not matched" before.
//	5  PyPI packages are matched (pep440).
//	6  Go modules and the Go standard library are matched (goversion).
const Version = 6

// Channels, as in advisory_affected.channel.
const (
	ChannelStandard  = osv.ChannelStandard
	ChannelUbuntuPro = osv.ChannelUbuntuPro
)

// Row is one advisory_affected row joined with its advisory.
type Row struct {
	AdvisoryID   string
	VulnKey      string   // advisories.vuln_key
	CVEIDs       []string // advisories.cve_ids
	Channel      string
	Introduced   string
	Fixed        *string
	LastAffected *string
	Severity     *string // distro severity (Debian urgency / Ubuntu priority)
	Status       string  // 'fixed' | 'unfixed' | 'not_affected' | 'ignored'
}

// PerCVE reports whether the row comes from a per-CVE record (as opposed
// to a DSA/DLA/USN/LSN notice).
func (r Row) PerCVE() bool { return osv.IsPerCVE(r.AdvisoryID) }

// keys returns the vuln_keys a row speaks for (see package doc).
func (r Row) keys() []string {
	if r.PerCVE() || len(r.CVEIDs) == 0 {
		return []string{r.VulnKey}
	}
	return r.CVEIDs
}

// Match is one positive match: a software_vulnerabilities row.
type Match struct {
	VulnKey       string
	AdvisoryIDs   []string // every advisory citing VulnKey for this source, sorted
	FixedVersion  *string  // nil = no fix available in any channel
	FixChannel    string   // "" (no fix) | ChannelStandard | ChannelUbuntuPro
	FixAdvisoryID string   // the advisory FixedVersion comes from ("" without a fix)
	Severity      *string  // distro severity of the deciding row
}

// RequiresPro reports whether the only available fix is in Ubuntu Pro.
func (m Match) RequiresPro() bool { return m.FixChannel == ChannelUbuntuPro }

// Stats counts rows Evaluate could not use.
type Stats struct {
	BadVersions int // rows whose introduced/fixed/last_affected did not parse
}

// state is one row's verdict for a version.
type state int

const (
	outOfRange state = iota // v < introduced
	affected
	fixedApplied // v >= fixed, or v > last_affected
)

// Evaluate returns the matches of installed source version v against rows
// (all rows for v's distro, release and source package), sorted by
// VulnKey. c is the ecosystem's comparator; the caller has checked that
// v is valid (c.Validate), so a comparison error means a bad row.
func Evaluate(v string, c Comparator, rows []Row) ([]Match, Stats) {
	var st Stats
	_, anyRange := c.(osvRanges)
	type group struct {
		perCVE, notice []int // indexes into rows
		refs           map[string]bool
	}
	groups := map[string]*group{}
	for i, r := range rows {
		if r.Status == "not_affected" || r.Status == "ignored" {
			continue
		}
		for _, k := range r.keys() {
			g := groups[k]
			if g == nil {
				g = &group{refs: map[string]bool{}}
				groups[k] = g
			}
			g.refs[r.AdvisoryID] = true
			if r.PerCVE() {
				g.perCVE = append(g.perCVE, i)
			} else {
				g.notice = append(g.notice, i)
			}
		}
	}

	var out []Match
	for key, g := range groups {
		deciding := g.perCVE
		if len(deciding) == 0 {
			deciding = g.notice
		}
		var std, pro []int
		for _, i := range deciding {
			if rows[i].Channel == ChannelUbuntuPro {
				pro = append(pro, i)
			} else {
				std = append(std, i)
			}
		}
		sv, bad1 := channelVerdict(v, c, rows, std, anyRange)
		pv, bad2 := channelVerdict(v, c, rows, pro, anyRange)
		st.BadVersions += bad1 + bad2
		m, ok := combine(sv, pv)
		if !ok {
			continue
		}
		m.VulnKey = key
		for id := range g.refs {
			m.AdvisoryIDs = append(m.AdvisoryIDs, id)
		}
		slices.Sort(m.AdvisoryIDs)
		out = append(out, m)
	}
	slices.SortFunc(out, func(a, b Match) int { return strings.Compare(a.VulnKey, b.VulnKey) })
	return out, st
}

// verdict is one channel's combined answer.
type verdict struct {
	present  bool // the channel has at least one usable row
	affected bool
	fix      *string // lowest fixed version among affected rows
	fixFrom  string  // its advisory
	severity *string
}

func channelVerdict(v string, c Comparator, rows []Row, idx []int, anyRange bool) (verdict, int) {
	var (
		out      verdict
		bad      int
		anyFixed bool
		fixSev   *string // severity of the row the fix comes from
		firstSev *string // first non-nil severity among affected rows
	)
	for _, i := range idx {
		r := rows[i]
		s, ok := rowState(v, c, r)
		if !ok {
			bad++
			continue
		}
		out.present = true
		switch s {
		case fixedApplied:
			// Under OSV range semantics v is only outside this range.
			anyFixed = anyFixed || !anyRange
		case affected:
			out.affected = true
			// rowState compared r.Fixed successfully, so both parse.
			if r.Fixed != nil && (out.fix == nil || less(c, *r.Fixed, *out.fix)) {
				out.fix, out.fixFrom, fixSev = r.Fixed, r.AdvisoryID, r.Severity
			}
			if firstSev == nil {
				firstSev = r.Severity
			}
		}
	}
	if anyFixed {
		out.affected, out.fix, out.fixFrom = false, nil, ""
		return out, bad
	}
	out.severity = fixSev
	if out.severity == nil {
		out.severity = firstSev
	}
	return out, bad
}

func rowState(v string, c Comparator, r Row) (state, bool) {
	if r.Introduced != "" && r.Introduced != "0" {
		d, err := c.Compare(v, r.Introduced)
		if err != nil {
			return 0, false
		}
		if d < 0 {
			return outOfRange, true
		}
	}
	switch {
	case r.Fixed != nil:
		d, err := c.Compare(v, *r.Fixed)
		if err != nil {
			return 0, false
		}
		if d < 0 {
			return affected, true
		}
		return fixedApplied, true
	case r.LastAffected != nil:
		d, err := c.Compare(v, *r.LastAffected)
		if err != nil {
			return 0, false
		}
		if d <= 0 {
			return affected, true
		}
		return fixedApplied, true
	}
	return affected, true
}

// less reports a < b; false when either doesn't parse.
func less(c Comparator, a, b string) bool {
	d, err := c.Compare(a, b)
	return err == nil && d < 0
}

// combine applies the channel rules from the package doc.
func combine(std, pro verdict) (Match, bool) {
	if std.present && !std.affected {
		return Match{}, false
	}
	if pro.present && !pro.affected {
		return Match{}, false
	}
	if !std.affected && !pro.affected {
		return Match{}, false
	}
	var m Match
	switch {
	case std.affected && std.fix != nil:
		m.FixedVersion, m.FixChannel, m.FixAdvisoryID = std.fix, ChannelStandard, std.fixFrom
	case pro.affected && pro.fix != nil:
		m.FixedVersion, m.FixChannel, m.FixAdvisoryID = pro.fix, ChannelUbuntuPro, pro.fixFrom
	}
	if std.affected {
		m.Severity = std.severity
	} else {
		m.Severity = pro.severity
	}
	return m, true
}

// MaxStandardFix is the highest standard-channel fixed version among ms
// (software_versions.max_fixed_version: "upgrading to this from the normal
// archive fixes everything fixable"), or nil. Pro-only fixes are left out:
// they are not installable without Ubuntu Pro. c is the ecosystem's
// comparator; fixed versions that don't parse are skipped.
func MaxStandardFix(c Comparator, ms []Match) *string {
	var best *string
	for _, m := range ms {
		if m.FixChannel != ChannelStandard || m.FixedVersion == nil || c.Validate(*m.FixedVersion) != nil {
			continue
		}
		if best == nil || less(c, *best, *m.FixedVersion) {
			best = m.FixedVersion
		}
	}
	return best
}

// SameMatches reports whether two match sets (each sorted by VulnKey) are
// identical, i.e. re-materializing would change nothing a finding shows.
func SameMatches(a, b []Match) bool {
	return slices.EqualFunc(a, b, func(x, y Match) bool {
		return x.VulnKey == y.VulnKey && eqPtr(x.FixedVersion, y.FixedVersion) &&
			x.FixChannel == y.FixChannel && x.FixAdvisoryID == y.FixAdvisoryID &&
			eqPtr(x.Severity, y.Severity) && slices.Equal(x.AdvisoryIDs, y.AdvisoryIDs)
	})
}

func eqPtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// SortMatches sorts by VulnKey (the order Evaluate returns and SameMatches
// expects), for matches loaded from the database.
func SortMatches(ms []Match) {
	slices.SortFunc(ms, func(a, b Match) int { return cmp.Compare(a.VulnKey, b.VulnKey) })
}
