// Package findings turns a host's current matches into vulnerable_package
// findings and runs their open/resolved lifecycle (DOMAIN_MODEL.md §2.6).
// It is pure; the store loads the inputs and writes the Plan.
//
// One finding per (host, source package, vuln_key), with
// dedup_key = "pkg:<source>:<vuln_key>", so one openssl CVE is one finding
// however many binaries (libssl3, openssl, libssl-dev) carry it.
//
// Lifecycle, per dedup_key:
//
//	not present, now matched   -> open     (first_seen_at = now)
//	open, still matched        -> open     (attributes refreshed, last_seen_at = now)
//	open, no longer matched    -> resolved (resolved_at = now): upgraded, removed,
//	                              advisory withdrawn/changed, or kernel no longer running
//	resolved, matched again    -> open     (reopened_at = now, reopen_count++,
//	                              first_seen_at kept, resolved_at cleared)
//	resolved, not matched      -> untouched
package findings

import (
	"slices"
	"strings"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/debversion"
	"github.com/pippinmole/upkeep.sh/server/internal/matcher"
	"github.com/pippinmole/upkeep.sh/server/internal/severity"
)

const (
	KindVulnerablePackage = "vulnerable_package"
	StatusOpen            = "open"
	StatusResolved        = "resolved"
)

// DedupKey is findings.dedup_key for a package vulnerability.
func DedupKey(source, vulnKey string) string { return "pkg:" + source + ":" + vulnKey }

// HostMatch is one current (host, binary version, vuln) match row:
// an open host_software range joined with software_versions and
// software_vulnerabilities.
type HostMatch struct {
	SoftwareID    int64
	Package       string // binary name
	Source        string // software_versions.match_source
	Version       string // software_versions.match_version (compared source version)
	KernelRelease string // software_versions.kernel_release ("" = not a kernel binary)
	Match         matcher.Match
}

// CVE is the per-CVE enrichment used for ranking (a cves row).
type CVE struct {
	KEV            bool
	EPSS           *float64
	EPSSPercentile *float64
	CVSS           *float64
}

// Desired is one finding that should be open.
type Desired struct {
	DedupKey, VulnKey, Source string
	InstalledVersion          string // lowest installed source version carrying it
	FixedVersion              *string
	FixChannel                string // "" | standard | ubuntu-pro
	FixAdvisoryID             string
	AdvisoryIDs               []string
	DistroSeverity            *string
	SoftwareIDs               []int64
	Packages                  []string
	KernelRelease             string // for kernel findings: the kernel release it was raised for
	RunningKernelUnknown      bool
	CVE                       CVE
	Severity                  severity.Result
}

// RequiresPro: the only available fix is in Ubuntu Pro.
func (d Desired) RequiresPro() bool { return d.FixChannel == matcher.ChannelUbuntuPro }

// Assess computes a finding's severity from its match and CVE data. A fix
// counts as available only in the standard archive: a Pro-only fix is not
// something the host can install as it stands.
func Assess(distroSeverity *string, fixChannel string, c CVE) severity.Result {
	pri := severity.PriorityUnknown
	if distroSeverity != nil {
		pri = severity.ParsePriority(*distroSeverity)
	}
	return severity.Assess(severity.Input{
		KEV: c.KEV, EPSS: c.EPSS, CVSS: c.CVSS, DistroPriority: pri,
		FixAvailable: fixChannel == matcher.ChannelStandard,
	})
}

// Build groups a host's current matches into desired findings, applying
// the running-kernel policy (matcher.RaisesFinding). runningKernel is ""
// when unknown. cves maps vuln_key to its enrichment (missing = none).
// The result is sorted by DedupKey.
func Build(rows []HostMatch, runningKernel string, cves map[string]CVE) []Desired {
	type acc struct {
		d    Desired
		minV debversion.Version
		ok   bool // minV set
	}
	by := map[string]*acc{}
	for _, r := range rows {
		raise, unknown := matcher.RaisesFinding(r.KernelRelease, runningKernel)
		if !raise || r.Source == "" {
			continue
		}
		key := DedupKey(r.Source, r.Match.VulnKey)
		a := by[key]
		if a == nil {
			a = &acc{d: Desired{DedupKey: key, VulnKey: r.Match.VulnKey, Source: r.Source}}
			by[key] = a
		}
		a.d.SoftwareIDs = append(a.d.SoftwareIDs, r.SoftwareID)
		a.d.Packages = append(a.d.Packages, r.Package)
		a.d.AdvisoryIDs = append(a.d.AdvisoryIDs, r.Match.AdvisoryIDs...)
		a.d.RunningKernelUnknown = a.d.RunningKernelUnknown || unknown
		// The binary with the lowest installed version decides what the
		// finding shows (installed, fixed-in, fix channel): it is the one
		// still needing the upgrade.
		v, err := debversion.Parse(r.Version)
		lower := err == nil && (!a.ok || debversion.Compare(v, a.minV) < 0)
		if lower || a.d.InstalledVersion == "" {
			if err == nil {
				a.minV, a.ok = v, true
			}
			a.d.InstalledVersion = r.Version
			a.d.FixedVersion = r.Match.FixedVersion
			a.d.FixChannel = r.Match.FixChannel
			a.d.FixAdvisoryID = r.Match.FixAdvisoryID
			a.d.DistroSeverity = r.Match.Severity
			a.d.KernelRelease = r.KernelRelease
		}
	}
	out := make([]Desired, 0, len(by))
	for _, a := range by {
		d := a.d
		slices.Sort(d.SoftwareIDs)
		d.SoftwareIDs = slices.Compact(d.SoftwareIDs)
		slices.Sort(d.Packages)
		d.Packages = slices.Compact(d.Packages)
		slices.Sort(d.AdvisoryIDs)
		d.AdvisoryIDs = slices.Compact(d.AdvisoryIDs)
		d.CVE = cves[d.VulnKey]
		d.Severity = Assess(d.DistroSeverity, d.FixChannel, d.CVE)
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b Desired) int { return strings.Compare(a.DedupKey, b.DedupKey) })
	return out
}

// Existing is the lifecycle state of a stored vulnerable_package finding.
type Existing struct {
	ID          string
	DedupKey    string
	Status      string
	FirstSeenAt time.Time
	ReopenedAt  *time.Time
	ReopenCount int
}

// Upsert is one finding to write as open.
type Upsert struct {
	Desired
	FirstSeenAt time.Time
	ReopenedAt  *time.Time
	ReopenCount int
	New         bool // no row existed
	Reopened    bool // the row was resolved
}

// Plan is what reconciliation writes.
type Plan struct {
	Upserts []Upsert // every desired finding (new, kept or reopened)
	Resolve []string // ids of open findings no longer matched
}

// Counts summarizes a Plan.
func (p Plan) Counts() (opened, reopened, kept, resolved int) {
	for _, u := range p.Upserts {
		switch {
		case u.New:
			opened++
		case u.Reopened:
			reopened++
		default:
			kept++
		}
	}
	return opened, reopened, kept, len(p.Resolve)
}

// Reconcile computes the lifecycle transitions from the stored findings
// to the desired set at time now.
func Reconcile(existing []Existing, desired []Desired, now time.Time) Plan {
	byKey := make(map[string]Existing, len(existing))
	for _, e := range existing {
		byKey[e.DedupKey] = e
	}
	var p Plan
	want := make(map[string]bool, len(desired))
	for _, d := range desired {
		want[d.DedupKey] = true
		u := Upsert{Desired: d}
		e, ok := byKey[d.DedupKey]
		switch {
		case !ok:
			u.New, u.FirstSeenAt = true, now
		case e.Status == StatusResolved:
			u.Reopened, u.FirstSeenAt = true, e.FirstSeenAt
			t := now
			u.ReopenedAt, u.ReopenCount = &t, e.ReopenCount+1
		default:
			u.FirstSeenAt, u.ReopenedAt, u.ReopenCount = e.FirstSeenAt, e.ReopenedAt, e.ReopenCount
		}
		p.Upserts = append(p.Upserts, u)
	}
	for _, e := range existing {
		if e.Status == StatusOpen && !want[e.DedupKey] {
			p.Resolve = append(p.Resolve, e.ID)
		}
	}
	slices.Sort(p.Resolve)
	return p
}
