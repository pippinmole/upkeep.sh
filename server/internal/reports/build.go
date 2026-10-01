package reports

import (
	"cmp"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/findings"
	"github.com/pippinmole/upkeep.sh/server/internal/matcher"
	"github.com/pippinmole/upkeep.sh/server/internal/severity"
)

// The report's rules (RankingVersion 1). Changing any of them is a
// RankingVersion bump.
//
//   - Host actions: open vulnerable_package findings with a fixed version
//     (either channel), grouped by (ecosystem, distro, release, source
//     package, fix channel). The group's fixed version is the highest of
//     its findings' by the ecosystem's comparator, so one upgrade closes
//     every CVE on the line. The release is part of the key because fixed
//     versions are per release (jammy's and noble's differ), and the
//     channel because an Ubuntu Pro fix can't be installed without Pro and
//     must not make standard fixes look like they need it.
//   - Image actions: open vulnerable_image findings grouped by image key.
//     Fixable = a fix in the standard channel (what a re-pull or rebuild
//     can pick up; findings.fix_channel = 'standard', as the Overview
//     counts it). An image with no fixable finding is not an action.
//   - No fix: host findings without a fixed version, and image findings
//     that aren't fixable. Never an action.
//   - Tier of a finding: KEV -> patch now; bucket critical or high, or
//     EPSS >= severity.EPSSHigh -> patch this week; else when convenient.
//     An action's tier is its most urgent finding's; its KEV, worst
//     severity, max EPSS and oldest open date are over the findings it
//     closes (for an image, its fixable findings).

// tiers in order, most urgent first; a tier's index is its rank.
var tiers = []string{TierPatchNow, TierPatchThisWeek, TierWhenConvenient}

func findingTier(f InputFinding) int {
	switch {
	case f.KEV:
		return 0
	case f.Severity >= severity.BucketHigh, f.EPSS != nil && *f.EPSS >= severity.EPSSHigh:
		return 1
	}
	return 2
}

func tierRank(t string) int { return slices.Index(tiers, t) }

// imageFixable: a fix a re-pull or rebuild can pick up.
func imageFixable(f InputFinding) bool {
	return f.FixedVersion != nil && f.FixChannel == matcher.ChannelStandard
}

// Build turns one estate's inputs into a report snapshot generated at now.
// It is pure: the same inputs give the same snapshot, lists in a
// deterministic order. Changes is left nil (see Compare).
func Build(in Inputs, sched ScheduleRef, trigger string, period Period, now time.Time) Snapshot {
	hosts := make(map[string]HostRef, len(in.Hosts))
	for _, h := range in.Hosts {
		hosts[h.ID] = HostRef(h)
	}
	ref := func(id string) HostRef {
		if h, ok := hosts[id]; ok {
			return h
		}
		return HostRef{ID: id, Name: id}
	}

	s := Snapshot{
		SchemaVersion:  SchemaVersion,
		RankingVersion: RankingVersion,
		GeneratedAt:    now.UTC(),
		Period:         Period{Start: period.Start.UTC(), End: period.End.UTC()},
		Trigger:        trigger,
		Schedule:       sched,
	}
	s.HostActions = buildHostActions(in.Findings, ref)
	s.ImageActions = buildImageActions(in, ref)
	s.NoFix = buildNoFix(in.Findings)
	s.RebootsRequired = buildReboots(in.Reboots, ref)
	s.Coverage = buildCoverage(in, ref)
	s.Hosts = buildHostSummaries(in, s)

	images := map[ImageKey]bool{}
	for _, c := range in.Containers {
		if c.Image != nil {
			images[*c.Image] = true
		}
	}
	s.Estate = Estate{Hosts: len(in.Hosts), Containers: len(in.Containers), Images: len(images)}

	h := &s.Headline
	for _, a := range s.HostActions {
		h.addTier(a.Tier)
	}
	for _, a := range s.ImageActions {
		h.addTier(a.Tier)
	}
	h.ImagesToUpdate = len(s.ImageActions)
	h.RebootsRequired = len(s.RebootsRequired)
	h.NoFixFindings = s.NoFix.Findings
	h.TotalOpenFindings = len(in.Findings)
	h.OpenedSinceLast, h.ResolvedSinceLast = in.Opened, in.Resolved
	h.StaleAgents = len(s.Coverage.StaleAgents)
	return s
}

func (h *Headline) addTier(t string) {
	switch t {
	case TierPatchNow:
		h.PatchNow++
	case TierPatchThisWeek:
		h.PatchThisWeek++
	default:
		h.WhenConvenient++
	}
}

// group accumulates the findings of one action line.
type group struct {
	tier     int
	kev      bool
	worst    severity.Bucket
	maxEPSS  *float64
	oldest   time.Time
	hostIDs  map[string]bool
	vulnKeys map[string]bool
	packages map[string]bool
}

func newGroup() *group {
	return &group{tier: len(tiers), hostIDs: map[string]bool{}, vulnKeys: map[string]bool{}, packages: map[string]bool{}}
}

func (g *group) add(f InputFinding) {
	g.tier = min(g.tier, findingTier(f))
	g.kev = g.kev || f.KEV
	g.worst = max(g.worst, f.Severity)
	if f.EPSS != nil && (g.maxEPSS == nil || *f.EPSS > *g.maxEPSS) {
		e := *f.EPSS
		g.maxEPSS = &e
	}
	if g.oldest.IsZero() || f.FirstSeenAt.Before(g.oldest) {
		g.oldest = f.FirstSeenAt
	}
	g.hostIDs[f.HostID] = true
	g.vulnKeys[f.VulnKey] = true
	for _, p := range f.Packages {
		g.packages[p] = true
	}
}

func (g *group) hosts(ref func(string) HostRef) []HostRef {
	out := make([]HostRef, 0, len(g.hostIDs))
	for id := range g.hostIDs {
		out = append(out, ref(id))
	}
	sortHostRefs(out)
	return out
}

func sortHostRefs(hs []HostRef) {
	slices.SortFunc(hs, func(a, b HostRef) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID)) })
}

func sortedKeys(m map[string]bool) []string {
	out := slices.Collect(maps.Keys(m))
	if out == nil {
		out = []string{}
	}
	slices.Sort(out)
	return out
}

type hostActionKey struct {
	ecosystem, distro, release, source, channel string
}

func buildHostActions(fs []InputFinding, ref func(string) HostRef) []HostAction {
	groups := map[hostActionKey]*group{}
	fixed := map[hostActionKey]string{}
	for _, f := range fs {
		if f.Kind != findings.KindVulnerablePackage || f.FixedVersion == nil {
			continue
		}
		k := hostActionKey{f.Ecosystem, f.Distro, f.Release, f.SourcePackage, f.FixChannel}
		g, ok := groups[k]
		if !ok {
			g = newGroup()
			groups[k] = g
			fixed[k] = *f.FixedVersion
		} else if versionLess(k.ecosystem, fixed[k], *f.FixedVersion) {
			fixed[k] = *f.FixedVersion
		}
		g.add(f)
	}

	type line struct {
		key hostActionKey
		HostAction
	}
	lines := make([]line, 0, len(groups))
	for k, g := range groups {
		a := HostAction{
			Tier:           tiers[g.tier],
			Package:        k.source,
			BinaryPackages: sortedKeys(g.packages),
			FixedVersion:   fixed[k],
			FixChannel:     k.channel,
			RequiresPro:    k.channel == matcher.ChannelUbuntuPro,
			KEV:            g.kev,
			WorstSeverity:  g.worst.String(),
			MaxEPSS:        g.maxEPSS,
			CVEs:           sortedKeys(g.vulnKeys),
			Hosts:          g.hosts(ref),
			OldestOpenAt:   g.oldest.UTC(),
		}
		a.CVECount, a.HostCount = len(a.CVEs), len(a.Hosts)
		lines = append(lines, line{k, a})
	}
	slices.SortFunc(lines, func(a, b line) int {
		return cmp.Or(
			compareUrgency(a.Tier, a.KEV, a.WorstSeverity, a.HostCount, b.Tier, b.KEV, b.WorstSeverity, b.HostCount),
			cmp.Compare(a.Package, b.Package),
			cmp.Compare(a.key.distro, b.key.distro),
			cmp.Compare(a.key.release, b.key.release),
			cmp.Compare(a.key.ecosystem, b.key.ecosystem),
			cmp.Compare(a.FixChannel, b.FixChannel),
			cmp.Compare(a.FixedVersion, b.FixedVersion),
		)
	})
	out := make([]HostAction, len(lines))
	for i, l := range lines {
		out[i] = l.HostAction
	}
	return out
}

// compareUrgency orders actions most urgent first: tier, then KEV, then
// worst severity, then the number of hosts affected.
func compareUrgency(ta string, ka bool, sa string, ha int, tb string, kb bool, sb string, hb int) int {
	return cmp.Or(
		cmp.Compare(tierRank(ta), tierRank(tb)),
		-cmp.Compare(boolInt(ka), boolInt(kb)),
		-cmp.Compare(bucketOf(sa), bucketOf(sb)),
		-cmp.Compare(ha, hb),
	)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// bucketOf inverts severity.Bucket.String.
func bucketOf(name string) severity.Bucket {
	for b := severity.BucketNegligible; b <= severity.BucketCritical; b++ {
		if b.String() == name {
			return b
		}
	}
	return severity.BucketUnknown
}

// versionLess reports a < b in the ecosystem's version order. A version
// the comparator rejects sorts below a valid one; two it can't order
// (invalid, unknown ecosystem, or equal but spelled differently) fall back
// to byte order, so the result never depends on input order.
func versionLess(ecosystem, a, b string) bool {
	if c, ok := matcher.ComparatorFor(ecosystem); ok {
		va, vb := c.Validate(a) == nil, c.Validate(b) == nil
		switch {
		case va && vb:
			if d, err := c.Compare(a, b); err == nil && d != 0 {
				return d < 0
			}
		case va != vb:
			return vb
		}
	}
	return a < b
}

func buildImageActions(in Inputs, ref func(string) HostRef) []ImageAction {
	type imageGroup struct {
		*group
		open, fixable int
		using         map[string]bool // hosts with a finding for or a container using the image
	}
	groups := map[ImageKey]*imageGroup{}
	for _, f := range in.Findings {
		if f.Kind != findings.KindVulnerableImage || f.Image == nil {
			continue
		}
		g, ok := groups[*f.Image]
		if !ok {
			g = &imageGroup{group: newGroup(), using: map[string]bool{}}
			groups[*f.Image] = g
		}
		g.open++
		g.using[f.HostID] = true
		if imageFixable(f) {
			g.fixable++
			g.add(f)
		}
	}

	refs := map[ImageKey][]string{}
	for _, im := range in.Images {
		refs[im.Key] = im.Refs
	}
	containers := map[ImageKey]map[string]bool{}
	for _, c := range in.Containers {
		if c.Image == nil || groups[*c.Image] == nil {
			continue
		}
		if containers[*c.Image] == nil {
			containers[*c.Image] = map[string]bool{}
		}
		containers[*c.Image][c.Name] = true
		groups[*c.Image].using[c.HostID] = true
	}

	out := []ImageAction{}
	for k, g := range groups {
		if g.fixable == 0 {
			continue
		}
		// Every host using the image, not only those with a fixable finding.
		g.hostIDs = g.using
		a := ImageAction{
			Tier:            tiers[g.tier],
			ImageID:         k.ImageID,
			ImageRefs:       orEmpty(refs[k]),
			OS:              k.OS,
			Arch:            k.Arch,
			Variant:         k.Variant,
			KEV:             g.kev,
			WorstSeverity:   g.worst.String(),
			MaxEPSS:         g.maxEPSS,
			OpenFindings:    g.open,
			FixableFindings: g.fixable,
			Containers:      sortedKeys(containers[k]),
			Hosts:           g.hosts(ref),
			OldestOpenAt:    g.oldest.UTC(),
		}
		out = append(out, a)
	}
	slices.SortFunc(out, func(a, b ImageAction) int {
		return cmp.Or(
			compareUrgency(a.Tier, a.KEV, a.WorstSeverity, len(a.Hosts), b.Tier, b.KEV, b.WorstSeverity, len(b.Hosts)),
			cmp.Compare(a.ImageID, b.ImageID),
			cmp.Compare(a.OS, b.OS),
			cmp.Compare(a.Arch, b.Arch),
			cmp.Compare(a.Variant, b.Variant),
		)
	})
	return out
}

// noFix reports whether an open finding counts under NoFix.
func noFix(f InputFinding) bool {
	if f.Kind == findings.KindVulnerableImage {
		return !imageFixable(f)
	}
	return f.FixedVersion == nil
}

func buildNoFix(fs []InputFinding) NoFix {
	var n NoFix
	var worst severity.Bucket
	for _, f := range fs {
		if !noFix(f) {
			continue
		}
		n.Findings++
		if f.KEV {
			n.KEVFindings++
		}
		if f.Kind == findings.KindVulnerableImage {
			n.ImageFindings++
		} else {
			n.HostPackageFindings++
		}
		worst = max(worst, f.Severity)
	}
	if n.Findings > 0 {
		w := worst.String()
		n.WorstSeverity = &w
	}
	return n
}

func buildReboots(rs []InputReboot, ref func(string) HostRef) []Reboot {
	out := make([]Reboot, 0, len(rs))
	for _, r := range rs {
		h := ref(r.HostID)
		pkgs := slices.Clone(orEmpty(r.Packages))
		slices.Sort(pkgs)
		out = append(out, Reboot{HostID: h.ID, HostName: h.Name, Packages: slices.Compact(pkgs), Since: utc(r.Since)})
	}
	slices.SortFunc(out, func(a, b Reboot) int {
		return cmp.Or(cmp.Compare(a.HostName, b.HostName), cmp.Compare(a.HostID, b.HostID))
	})
	return out
}

func buildCoverage(in Inputs, ref func(string) HostRef) Coverage {
	c := Coverage{
		StaleAgents:        make([]StaleAgent, 0, len(in.StaleAgents)),
		HostsWithoutDocker: make([]HostRef, 0, len(in.HostsWithoutDocker)),
		ImagesNotScored:    []ImageNotScored{},
	}
	for _, a := range in.StaleAgents {
		hs := make([]HostRef, 0, len(a.HostIDs))
		for _, id := range a.HostIDs {
			hs = append(hs, ref(id))
		}
		sortHostRefs(hs)
		c.StaleAgents = append(c.StaleAgents, StaleAgent{AgentID: a.ID, Name: a.Name, LastSeenAt: utc(a.LastSeenAt), Hosts: hs})
	}
	slices.SortFunc(c.StaleAgents, func(a, b StaleAgent) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.AgentID, b.AgentID))
	})
	for _, id := range in.HostsWithoutDocker {
		c.HostsWithoutDocker = append(c.HostsWithoutDocker, ref(id))
	}
	sortHostRefs(c.HostsWithoutDocker)
	for _, im := range in.Images {
		if im.NotScored == "" {
			continue
		}
		c.ImagesNotScored = append(c.ImagesNotScored, ImageNotScored{
			ImageID: im.Key.ImageID, ImageRefs: orEmpty(im.Refs),
			OS: im.Key.OS, Arch: im.Key.Arch, Variant: im.Key.Variant, Status: im.NotScored,
		})
	}
	slices.SortFunc(c.ImagesNotScored, func(a, b ImageNotScored) int {
		return cmp.Or(
			cmp.Compare(strings.Join(a.ImageRefs, ","), strings.Join(b.ImageRefs, ",")),
			cmp.Compare(a.ImageID, b.ImageID), cmp.Compare(a.OS, b.OS),
			cmp.Compare(a.Arch, b.Arch), cmp.Compare(a.Variant, b.Variant),
		)
	})
	return c
}

func buildHostSummaries(in Inputs, s Snapshot) []HostSummary {
	byID := make(map[string]*HostSummary, len(in.Hosts))
	out := make([]HostSummary, len(in.Hosts))
	for i, h := range in.Hosts {
		out[i] = HostSummary{ID: h.ID, Name: h.Name}
		byID[h.ID] = &out[i]
	}
	tier := func(h *HostSummary, t string) {
		switch t {
		case TierPatchNow:
			h.PatchNow++
		case TierPatchThisWeek:
			h.PatchThisWeek++
		default:
			h.WhenConvenient++
		}
	}
	for _, a := range s.HostActions {
		for _, r := range a.Hosts {
			if h := byID[r.ID]; h != nil {
				tier(h, a.Tier)
			}
		}
	}
	for _, a := range s.ImageActions {
		for _, r := range a.Hosts {
			if h := byID[r.ID]; h != nil {
				tier(h, a.Tier)
				h.ImagesToUpdate++
			}
		}
	}
	for _, r := range s.RebootsRequired {
		if h := byID[r.HostID]; h != nil {
			h.RebootRequired = true
		}
	}
	for _, f := range in.Findings {
		if h := byID[f.HostID]; h != nil {
			h.TotalOpenFindings++
			if noFix(f) {
				h.NoFixFindings++
			}
		}
	}
	slices.SortFunc(out, func(a, b HostSummary) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID)) })
	return out
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
