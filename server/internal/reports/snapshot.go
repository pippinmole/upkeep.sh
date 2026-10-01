// Package reports builds scheduled estate reports (docs/tasks/
// phase-1-7-reports.md, docs/decisions/scheduled-reports.md): the state of
// a user's whole estate at one moment, ranked into actions, stored as a
// JSON snapshot in reports.snapshot and compared with the schedule's
// previous report.
//
// This file is the snapshot contract. Every consumer reads the stored
// JSON, so it is shared across runtimes: the webhook channel sends it as
// is (docs/WEBHOOKS.md), the dashboard and the email template read it
// (web/src/lib/report-snapshot.ts mirrors these types by hand), and the
// next run compares against it. The fixture web/src/lib/
// report-snapshot.example.json exercises every field; snapshot_test.go
// round-trips it through these types and the web type-checks it, so the
// two sides can't drift silently.
//
// Conventions:
//   - Lists are complete (no truncation; "…and N more" is a rendering
//     concern) and never null: an empty list is [].
//   - Optional scalars are present as null, never omitted.
//   - Timestamps are RFC 3339 in UTC.
//   - Severities are severity.Bucket names ("critical" … "negligible").
//   - No URLs: the dashboard's base URL can change after a report is
//     stored, so channels build links at send time.
//   - Hosts are named as the dashboard names them: the label if set, else
//     the hostname.
package reports

import "time"

// SchemaVersion is Snapshot.SchemaVersion: the shape of this JSON. Bump it
// on breaking changes (a removed or retyped field); readers of stored
// snapshots must handle every version still within retention (a year).
const SchemaVersion = 1

// RankingVersion is the version of the report's own definitions: which
// findings go into which tier, what counts as an image to update, a
// reboot, a finding with no fix. Bump it whenever those rules change, so
// the comparison with a previous report built under other rules is
// suppressed (Changes.Comparable false) instead of reporting the rule
// change as a change in the estate. Independent of the severity package's
// ranking of individual findings.
const RankingVersion = 1

// Tiers of an action, most urgent first.
const (
	TierPatchNow       = "patch_now"       // any KEV finding
	TierPatchThisWeek  = "patch_this_week" // critical/high with a fix, or high EPSS
	TierWhenConvenient = "when_convenient" // the rest with a fix
)

// Report triggers (reports.trigger).
const (
	TriggerScheduled = "scheduled" // report_due
	TriggerManual    = "manual"    // "Send now" in the dashboard
)

// Schedule cadences (report_schedules.cadence).
const (
	CadenceWeekly  = "weekly"
	CadenceMonthly = "monthly"
)

// Snapshot is one report: the estate (every non-archived host of the user
// and the images its containers use) as of GeneratedAt.
type Snapshot struct {
	SchemaVersion  int         `json:"schema_version"`
	RankingVersion int         `json:"ranking_version"`
	GeneratedAt    time.Time   `json:"generated_at"`
	Period         Period      `json:"period"`
	Trigger        string      `json:"trigger"` // TriggerScheduled | TriggerManual
	Schedule       ScheduleRef `json:"schedule"`
	Estate         Estate      `json:"estate"`
	Headline       Headline    `json:"headline"`
	// Actions, sorted most urgent first (tier, then KEV, then severity).
	HostActions  []HostAction  `json:"host_actions"`
	ImageActions []ImageAction `json:"image_actions"`
	// Hosts whose last snapshot says a reboot is required.
	RebootsRequired []Reboot `json:"reboots_required"`
	NoFix           NoFix    `json:"no_fix"`
	// Always present, even when everything else is empty: "all clear"
	// with agents not reporting is false reassurance.
	Coverage Coverage `json:"coverage"`
	// Per-host counts, for attributing changes to hosts added or archived.
	Hosts []HostSummary `json:"hosts"`
	// The comparison with the schedule's previous report; nil (null) when
	// there is none.
	Changes *Changes `json:"changes"`
}

// Period is what the "since last report" numbers cover: from the previous
// report's generated_at (or, for a schedule's first report, one nominal
// period back) to GeneratedAt. Same as reports.period_start / period_end.
type Period struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ScheduleRef is the schedule as it was when the report was built.
type ScheduleRef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Cadence  string `json:"cadence"`  // CadenceWeekly | CadenceMonthly
	Timezone string `json:"timezone"` // IANA name
}

// Estate is what the report covers: non-archived hosts, their current
// containers (any state), and the distinct images (by image key) those
// containers use.
type Estate struct {
	Hosts      int `json:"hosts"`
	Containers int `json:"containers"`
	Images     int `json:"images"`
}

// Headline holds the report's top-line numbers. Its JSON keys are the
// metric keys of Changes.Metrics and HostChange.Contribution.
type Headline struct {
	// Action lines per tier, host packages and images together.
	PatchNow       int `json:"patch_now"`
	PatchThisWeek  int `json:"patch_this_week"`
	WhenConvenient int `json:"when_convenient"`
	// Image action lines (all tiers).
	ImagesToUpdate  int `json:"images_to_update"`
	RebootsRequired int `json:"reboots_required"`
	NoFixFindings   int `json:"no_fix_findings"`
	// Open findings of both kinds, with or without a fix.
	TotalOpenFindings int `json:"total_open_findings"`
	// Findings opened (or reopened) / resolved within Period.
	OpenedSinceLast   int `json:"opened_since_last"`
	ResolvedSinceLast int `json:"resolved_since_last"`
	StaleAgents       int `json:"stale_agents"`
}

// HostRef names a host.
type HostRef struct {
	ID   string `json:"id"`
	Name string `json:"name"` // label, else hostname
}

// HostAction is one host-package upgrade: open vulnerable_package findings
// grouped by (source package, fixed version). When the CVEs of a package
// need different versions, the fix is the highest, so one line closes them
// all.
type HostAction struct {
	Tier    string `json:"tier"`
	Package string `json:"package"` // source package
	// Installed binary packages built from it, across the hosts (what
	// the user actually upgrades).
	BinaryPackages []string `json:"binary_packages"`
	FixedVersion   string   `json:"fixed_version"`
	// "standard" | "ubuntu-pro" (matcher.ChannelStandard / ChannelUbuntuPro).
	FixChannel    string   `json:"fix_channel"`
	RequiresPro   bool     `json:"requires_pro"` // FixChannel == "ubuntu-pro"
	KEV           bool     `json:"kev"`
	WorstSeverity string   `json:"worst_severity"`
	MaxEPSS       *float64 `json:"max_epss"` // nil when no CVE has an EPSS score
	// Vulnerability keys closed (CVE ids where there is one), sorted.
	CVEs         []string  `json:"cves"`
	CVECount     int       `json:"cve_count"`
	Hosts        []HostRef `json:"hosts"`
	HostCount    int       `json:"host_count"`
	OldestOpenAt time.Time `json:"oldest_open_at"` // earliest first_seen_at of the group
}

// ImageAction is one image to re-pull or rebuild: open vulnerable_image
// findings grouped by image key (image_id, os, arch, variant).
type ImageAction struct {
	Tier          string   `json:"tier"`
	ImageID       string   `json:"image_id"`
	ImageRefs     []string `json:"image_refs"` // repo tags (digests when untagged)
	OS            string   `json:"os"`
	Arch          string   `json:"arch"`
	Variant       string   `json:"variant"` // "" when the platform has none
	KEV           bool     `json:"kev"`
	WorstSeverity string   `json:"worst_severity"`
	MaxEPSS       *float64 `json:"max_epss"`
	// Findings counted per (host, source package, vuln key), as the
	// findings table does; fixable = a fix in the standard channel.
	OpenFindings    int       `json:"open_findings"`
	FixableFindings int       `json:"fixable_findings"`
	Containers      []string  `json:"containers"` // container names, across hosts
	Hosts           []HostRef `json:"hosts"`
	OldestOpenAt    time.Time `json:"oldest_open_at"`
}

// Reboot is a host whose last snapshot has reboot_required.
type Reboot struct {
	HostID   string `json:"host_id"`
	HostName string `json:"host_name"`
	// Packages that asked for it (snapshots.reboot_packages), sorted.
	Packages []string `json:"packages"`
	// Since when, as far as the snapshots tell; nil when unknown.
	Since *time.Time `json:"since"`
}

// NoFix summarizes open findings with no fix yet: tracked, nothing to do.
type NoFix struct {
	Findings            int     `json:"findings"`
	KEVFindings         int     `json:"kev_findings"`
	WorstSeverity       *string `json:"worst_severity"` // nil when Findings is 0
	HostPackageFindings int     `json:"host_package_findings"`
	ImageFindings       int     `json:"image_findings"`
}

// Coverage lists what the report can't see.
type Coverage struct {
	StaleAgents        []StaleAgent     `json:"stale_agents"`
	HostsWithoutDocker []HostRef        `json:"hosts_without_docker"`
	ImagesNotScored    []ImageNotScored `json:"images_not_scored"`
}

// StaleAgent is an agent past the dashboard's staleness threshold (see
// agent_health), with the hosts it reports for.
type StaleAgent struct {
	AgentID    string     `json:"agent_id"`
	Name       string     `json:"name"`
	LastSeenAt *time.Time `json:"last_seen_at"` // nil = never seen
	Hosts      []HostRef  `json:"hosts"`
}

// ImageNotScored is an image in use whose findings are unknown: no package
// list yet, the list failed, or it isn't scored yet (image_scores).
type ImageNotScored struct {
	ImageID   string   `json:"image_id"`
	ImageRefs []string `json:"image_refs"`
	OS        string   `json:"os"`
	Arch      string   `json:"arch"`
	Variant   string   `json:"variant"`
	// image_scores.list_status ("none" | "unavailable" | "error"), or
	// "pending" for an ok list without a current score.
	Status string `json:"status"`
}

// HostSummary is one host's share of the report. Action counts are the
// action lines that include the host.
type HostSummary struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	PatchNow          int    `json:"patch_now"`
	PatchThisWeek     int    `json:"patch_this_week"`
	WhenConvenient    int    `json:"when_convenient"`
	ImagesToUpdate    int    `json:"images_to_update"`
	RebootRequired    bool   `json:"reboot_required"`
	NoFixFindings     int    `json:"no_fix_findings"`
	TotalOpenFindings int    `json:"total_open_findings"`
}

// Changes compares this report with the schedule's previous one.
type Changes struct {
	PreviousReportID    string    `json:"previous_report_id"`
	PreviousGeneratedAt time.Time `json:"previous_generated_at"`
	// False when the previous report used another RankingVersion; Metrics
	// then omits every key whose definition depends on the ranking.
	Comparable bool `json:"comparable"`
	// Keyed by Headline JSON key.
	Metrics map[string]MetricChange `json:"metrics"`
	// Hosts in this report and not the previous one, and the reverse
	// (archived or deleted since), with their share of each metric (from
	// the report they appear in), so a change can be attributed.
	HostsAdded    []HostChange `json:"hosts_added"`
	HostsArchived []HostChange `json:"hosts_archived"`
}

// MetricChange is one headline number against the previous report.
type MetricChange struct {
	Previous int `json:"previous"`
	Current  int `json:"current"`
	Delta    int `json:"delta"` // Current - Previous
	// Delta / Previous * 100, rounded to one decimal; nil when Previous
	// is below 10 (0 -> 3 is not "+inf%", 1 -> 2 is not "+100%").
	Percent *float64 `json:"percent"`
}

// HostChange is a host added or archived between two reports.
type HostChange struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Keyed by Headline JSON key; only metrics a host has a share of.
	Contribution map[string]int `json:"contribution"`
}
