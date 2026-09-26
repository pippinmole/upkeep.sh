package osv

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// NormalizeVersion is folded into every content hash. Bump it whenever
// normalization output changes for the same input, so the next full sync
// rewrites every advisory (and marks their packages dirty for the matcher).
const NormalizeVersion = 1

// Channels for Affected.Channel (advisory_affected.channel).
const (
	ChannelStandard  = "standard"
	ChannelUbuntuPro = "ubuntu-pro" // OSV "Ubuntu:Pro:<ver>": ESM / Pro-only
)

// Release is one distro_releases row.
type Release struct {
	Distro    string // 'debian' | 'ubuntu'
	Codename  string
	Version   string // '12', '22.04'
	Supported bool
}

// Releases maps OSV ecosystem versions to codenames.
type Releases struct {
	byVersion map[string]Release // distro + "\x00" + version
}

func NewReleases(rs []Release) Releases {
	m := make(map[string]Release, len(rs))
	for _, r := range rs {
		m[r.Distro+"\x00"+r.Version] = r
	}
	return Releases{byVersion: m}
}

// Fingerprint identifies the supported set. The sync stores it and runs a
// full import when it changes (a release was enabled or disabled).
func (rs Releases) Fingerprint() string {
	var keys []string
	for _, r := range rs.byVersion {
		if r.Supported {
			keys = append(keys, r.Distro+"/"+r.Version+"/"+r.Codename)
		}
	}
	sort.Strings(keys)
	sum := sha256.Sum256([]byte(fmt.Sprintf("v%d|%s", NormalizeVersion, strings.Join(keys, ","))))
	return hex.EncodeToString(sum[:])
}

// Lookup resolves an OSV ecosystem string to a supported release and
// channel. ok is false for unsupported releases, unknown releases, and
// variant ecosystems we don't import (Ubuntu FIPS, Realtime,
// NVIDIA BlueField).
func (rs Releases) Lookup(ecosystem string) (rel Release, channel string, ok bool) {
	distro, version, channel, ok := ParseEcosystem(ecosystem)
	if !ok {
		return Release{}, "", false
	}
	rel, ok = rs.byVersion[distro+"\x00"+version]
	if !ok || !rel.Supported {
		return Release{}, "", false
	}
	return rel, channel, true
}

var releaseVersionRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

// ParseEcosystem splits an OSV Debian/Ubuntu ecosystem name.
//
//	Debian:12                -> debian 12    standard
//	Ubuntu:22.04:LTS         -> ubuntu 22.04 standard
//	Ubuntu:25.10             -> ubuntu 25.10 standard
//	Ubuntu:Pro:22.04:LTS     -> ubuntu 22.04 ubuntu-pro
//	Ubuntu:Pro:FIPS:20.04:LTS, Ubuntu:Pro:Realtime:24.04:LTS,
//	Ubuntu:Nvidia-BlueField:22.04:LTS, ... -> not ok (variant kernels/FIPS)
func ParseEcosystem(eco string) (distro, version, channel string, ok bool) {
	parts := strings.Split(eco, ":")
	channel = ChannelStandard
	switch {
	case len(parts) == 2 && parts[0] == "Debian":
		distro, version = "debian", parts[1]
	case len(parts) >= 2 && parts[0] == "Ubuntu":
		rest := parts[1:]
		if rest[0] == "Pro" {
			channel = ChannelUbuntuPro
			rest = rest[1:]
		}
		if len(rest) == 0 || len(rest) > 2 || (len(rest) == 2 && rest[1] != "LTS") {
			return "", "", "", false
		}
		distro, version = "ubuntu", rest[0]
	default:
		return "", "", "", false
	}
	if !releaseVersionRe.MatchString(version) {
		return "", "", "", false
	}
	return distro, version, channel, true
}

// SourceFor returns the advisories.source / feed name for an OSV ecosystem
// directory ("Debian" -> "osv-debian").
func SourceFor(ecosystemDir string) string {
	return "osv-" + strings.ToLower(ecosystemDir)
}

// Advisory is one normalized record: an advisories row plus its
// advisory_affected rows.
type Advisory struct {
	ID          string
	Source      string
	VulnKey     string
	CVEIDs      []string
	Aliases     []string
	Upstream    []string
	Related     []string
	Summary     string
	Details     string
	Severity    *string // record-level distro severity (Ubuntu priority)
	Published   *time.Time
	Modified    time.Time
	Withdrawn   *time.Time
	Raw         []byte
	ContentHash string
	// Affected is empty for withdrawn advisories: they are kept for
	// reference but must not match anything.
	Affected []AffectedRow

	// CVSSv3Vector is set on per-CVE records (DEBIAN-CVE-, UBUNTU-CVE-,
	// CVE-) and feeds cves.cvss_v3_vector for VulnKey.
	CVSSv3Vector string
}

// AffectedRow is one advisory_affected row.
type AffectedRow struct {
	Distro         string  `json:"d"`
	Release        string  `json:"r"`
	SourcePackage  string  `json:"p"`
	Channel        string  `json:"c"`
	Introduced     string  `json:"i"`
	FixedVersion   *string `json:"f,omitempty"`
	LastAffected   *string `json:"l,omitempty"`
	DistroSeverity *string `json:"s,omitempty"`
	Status         string  `json:"st"`
	Ecosystem      string  `json:"e"`
}

// Key is the (distro, release, source package) the matcher re-evaluates
// when rows under it change.
type Key struct {
	Distro, Release, SourcePackage string
}

func (a AffectedRow) Key() Key { return Key{a.Distro, a.Release, a.SourcePackage} }

// pk is the advisory_affected primary key within one advisory.
func (a AffectedRow) pk() string {
	return a.Distro + "\x00" + a.Release + "\x00" + a.SourcePackage + "\x00" + a.Channel + "\x00" + a.Introduced
}

var cveRe = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]+$`)

// IsCVE reports whether s is a CVE id.
func IsCVE(s string) bool { return cveRe.MatchString(s) }

// Normalize maps a record onto the advisory schema for the given releases.
// relevant is false when no affected entry is in a supported release: such
// records are not stored (and are deleted if previously stored).
func Normalize(r *Record, source string, rels Releases) (adv Advisory, relevant bool, err error) {
	adv = Advisory{
		ID: r.ID, Source: source,
		Aliases: nonNil(r.Aliases), Upstream: nonNil(r.Upstream), Related: nonNil(r.Related),
		Summary: r.Summary, Details: r.Details,
	}
	mod, err := parseTime(r.Modified)
	if err != nil || mod == nil {
		return adv, false, fmt.Errorf("osv %s: bad modified %q", r.ID, r.Modified)
	}
	adv.Modified = *mod
	if adv.Published, err = parseTime(r.Published); err != nil {
		return adv, false, fmt.Errorf("osv %s: bad published: %w", r.ID, err)
	}
	if adv.Withdrawn, err = parseTime(r.Withdrawn); err != nil {
		return adv, false, fmt.Errorf("osv %s: bad withdrawn: %w", r.ID, err)
	}

	adv.CVEIDs = cveIDs(r)
	adv.VulnKey = vulnKey(r.ID, adv.CVEIDs)
	adv.Severity = recordPriority(r.Severity)
	// Per-CVE records (own id is the CVE, or a DEBIAN-/UBUNTU-CVE wrapper):
	// their CVSS belongs to that CVE. Multi-CVE advisories (DSA/USN) are
	// skipped: their record-level severity isn't per CVE.
	if IsPerCVE(r.ID) {
		for _, s := range r.Severity {
			if s.Type == "CVSS_V3" && strings.HasPrefix(s.Score, "CVSS:3") {
				adv.CVSSv3Vector = s.Score // first one listed
				break
			}
		}
	}

	var (
		rows []AffectedRow
		keep []int
		seen = map[string]bool{}
	)
	for i, a := range r.Affected {
		rel, channel, ok := rels.Lookup(a.Package.Ecosystem)
		if !ok || a.Package.Name == "" {
			continue
		}
		sev := affectedSeverity(rel.Distro, a, adv.Severity)
		added := false
		for _, rg := range a.Ranges {
			if rg.Type != "ECOSYSTEM" {
				continue
			}
			for _, row := range rangeRows(rg.Events) {
				row.Distro, row.Release, row.SourcePackage = rel.Distro, rel.Codename, a.Package.Name
				row.Channel, row.Ecosystem, row.DistroSeverity = channel, a.Package.Ecosystem, sev
				if row.FixedVersion != nil {
					row.Status = "fixed"
				} else {
					row.Status = "unfixed"
				}
				// Duplicate keys happen when OSV lists a package twice for one
				// release (e.g. "Ubuntu:26.04" and "Ubuntu:26.04:LTS"); keep the first.
				if seen[row.pk()] {
					continue
				}
				seen[row.pk()] = true
				rows = append(rows, row)
				added = true
			}
		}
		if added {
			keep = append(keep, i)
		}
	}
	if len(rows) == 0 {
		return adv, false, nil
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].pk() < rows[j].pk() })
	if adv.Withdrawn == nil {
		adv.Affected = rows
	}

	if adv.Raw, err = r.trimmedRaw(keep); err != nil {
		return adv, false, fmt.Errorf("osv %s: trim raw: %w", r.ID, err)
	}
	adv.ContentHash = contentHash(adv)
	return adv, true, nil
}

// rangeRows turns an OSV event list into (introduced, fixed|last_affected)
// pairs. An introduced with no closing event is an unfixed row.
func rangeRows(events []Event) []AffectedRow {
	var (
		out  []AffectedRow
		open *AffectedRow
	)
	for _, e := range events {
		switch {
		case e.Introduced != nil:
			if open != nil {
				out = append(out, *open)
			}
			open = &AffectedRow{Introduced: *e.Introduced}
		case e.Fixed != nil && open != nil:
			v := *e.Fixed
			open.FixedVersion = &v
			out = append(out, *open)
			open = nil
		case e.LastAffected != nil && open != nil:
			v := *e.LastAffected
			open.LastAffected = &v
			out = append(out, *open)
			open = nil
		}
	}
	if open != nil {
		out = append(out, *open)
	}
	return out
}

// ubuntuPriorityRank orders Ubuntu priorities; unknown values rank 0.
var ubuntuPriorityRank = map[string]int{
	"untriaged": 1, "negligible": 2, "low": 3, "medium": 4, "high": 5, "critical": 6,
}

// affectedSeverity is the distro severity for one affected entry:
// Debian urgency, or Ubuntu's per-package priority, the highest per-CVE
// priority of a USN, or the record's priority.
func affectedSeverity(distro string, a Affected, recordSev *string) *string {
	if distro == "debian" {
		return normSeverity(a.EcosystemSpecific.Urgency)
	}
	if s := normSeverity(a.EcosystemSpecific.UbuntuPriority); s != nil {
		return s
	}
	if cm := a.DatabaseSpecific.CVEsMap; cm != nil {
		var best *string
		for _, c := range cm.CVEs {
			if s := recordPriority(c.Severity); s != nil &&
				(best == nil || ubuntuPriorityRank[*s] > ubuntuPriorityRank[*best]) {
				best = s
			}
		}
		if best != nil {
			return best
		}
	}
	if recordSev == nil {
		return nil
	}
	v := *recordSev
	return &v
}

// recordPriority extracts Ubuntu's priority from an OSV severity list
// (type "Ubuntu"; a few records omit the type but carry a priority word).
func recordPriority(sevs []Severity) *string {
	for _, s := range sevs {
		if s.Type == "Ubuntu" || (s.Type == "" && ubuntuPriorityRank[strings.ToLower(s.Score)] > 0) {
			return normSeverity(s.Score)
		}
	}
	return nil
}

// normSeverity lowercases a distro severity. Debian's "not yet assigned"
// means unknown and becomes NULL; trailing '*' markers are dropped.
func normSeverity(s string) *string {
	s = strings.TrimRight(strings.ToLower(strings.TrimSpace(s)), "*")
	if s == "" || s == "not yet assigned" {
		return nil
	}
	return &s
}

// IsPerCVE reports whether an advisory id is a per-CVE record (CVE-*,
// DEBIAN-CVE-*, UBUNTU-CVE-*) rather than a DSA/DLA/USN/LSN notice.
func IsPerCVE(id string) bool {
	return IsCVE(id) || strings.HasPrefix(id, "DEBIAN-CVE-") || strings.HasPrefix(id, "UBUNTU-CVE-")
}

// cveIDs collects every CVE the record refers to: its own id, the CVE a
// DEBIAN-CVE-/UBUNTU-CVE- id wraps, and CVE aliases/upstream ids.
func cveIDs(r *Record) []string {
	set := map[string]bool{}
	add := func(s string) {
		if IsCVE(s) {
			set[s] = true
		}
	}
	add(r.ID)
	for _, p := range []string{"DEBIAN-", "UBUNTU-"} {
		if strings.HasPrefix(r.ID, p+"CVE-") {
			add(strings.TrimPrefix(r.ID, p))
		}
	}
	for _, s := range r.Aliases {
		add(s)
	}
	for _, s := range r.Upstream {
		add(s)
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

// vulnKey is the canonical downstream key (DOMAIN_MODEL.md §2.4): the CVE
// for per-CVE records and single-CVE advisories, else the advisory id.
func vulnKey(id string, cves []string) string {
	if IsCVE(id) {
		return id
	}
	for _, p := range []string{"DEBIAN-", "UBUNTU-"} {
		if c := strings.TrimPrefix(id, p); c != id && IsCVE(c) {
			return c
		}
	}
	if len(cves) == 1 {
		return cves[0]
	}
	return id
}

func contentHash(a Advisory) string {
	h := sha256.New()
	enc := json.NewEncoder(h)
	_ = enc.Encode(struct {
		V                                 int
		ID, VulnKey, Summary, Details, CV string
		CVEs, Aliases, Upstream, Related  []string
		Sev                               *string
		Pub, Wd                           *time.Time
		Mod                               time.Time
		Rows                              []AffectedRow
		Raw                               json.RawMessage
	}{NormalizeVersion, a.ID, a.VulnKey, a.Summary, a.Details, a.CVSSv3Vector,
		a.CVEIDs, a.Aliases, a.Upstream, a.Related, a.Severity, a.Published, a.Withdrawn,
		a.Modified, a.Affected, a.Raw})
	return hex.EncodeToString(h.Sum(nil))
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
