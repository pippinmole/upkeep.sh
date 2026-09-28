package reports

import (
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/severity"
)

// Inputs is the raw state of one user's estate that Build turns into a
// Snapshot, loaded by store.LoadReportInputs in one read transaction.
// Everything is already scoped to the user's non-archived hosts; Build
// applies the report's rules (grouping, tiers, what counts as fixable) and
// does no filtering of its own.
type Inputs struct {
	// Non-archived hosts.
	Hosts []InputHost
	// Open vulnerable_package and vulnerable_image findings.
	Findings []InputFinding
	// Current containers (any state).
	Containers []InputContainer
	// Image keys the containers use, with their refs and scoring state.
	Images []InputImage
	// Hosts whose newest snapshot has reboot_required.
	Reboots []InputReboot
	// Agents past the staleness threshold that collect at least one of
	// the hosts.
	StaleAgents []InputAgent
	// Hosts whose newest snapshot has no ok docker_images collector.
	HostsWithoutDocker []string
	// Finding transitions within the report's period: opens (first seen
	// or reopened) and resolutions.
	Opened, Resolved int
}

// InputHost is a non-archived host.
type InputHost struct {
	ID   string
	Name string // label, else hostname
}

// ImageKey identifies an image as container_images does.
type ImageKey struct {
	ImageID, OS, Arch, Variant string
}

// InputFinding is one open finding (a findings row) of either kind.
type InputFinding struct {
	HostID string
	Kind   string // findings.KindVulnerablePackage | findings.KindVulnerableImage
	// Vulnerability key (the CVE id where there is one).
	VulnKey string
	// Source package, and the ecosystem / distro / release its binary
	// versions were interned under (software_versions); the version
	// comparator and the host-action grouping key use them. Empty for
	// image findings.
	SourcePackage              string
	Ecosystem, Distro, Release string
	// Installed binary packages built from the source (findings.packages).
	Packages     []string
	FixedVersion *string // nil = no fix in any channel
	FixChannel   string  // "" | "standard" | "ubuntu-pro"
	KEV          bool
	Severity     severity.Bucket
	EPSS         *float64
	FirstSeenAt  time.Time
	Image        *ImageKey // image findings only
}

// InputContainer is a current container.
type InputContainer struct {
	HostID string
	Name   string
	// The image key it runs; nil when the image was never inspected on
	// that host (no platform, so no key).
	Image *ImageKey
}

// InputImage is an image key in use.
type InputImage struct {
	Key  ImageKey
	Refs []string // repo tags across the hosts, else repo digests; sorted
	// ImageNotScored.Status when its findings are unknown ("none",
	// "unavailable", "error", "pending"), "" when scored.
	NotScored string
}

// InputReboot is a host whose newest snapshot has reboot_required.
type InputReboot struct {
	HostID   string
	Packages []string
	Since    *time.Time
}

// InputAgent is a stale agent.
type InputAgent struct {
	ID         string
	Name       string
	LastSeenAt *time.Time
	HostIDs    []string // non-archived hosts it collects
}
