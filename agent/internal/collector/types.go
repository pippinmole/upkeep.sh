// Package collector gathers read-only facts about a host: listening
// sockets, pending-reboot state and public IPs, and defines the snapshot
// wire types. Installed packages come from the pkgsource subpackage, one
// implementation per package ecosystem. Nothing here executes commands or
// mutates host state.
package collector

// SchemaVersion is bumped whenever the Snapshot payload shape changes in a
// way the server needs to branch on. Additive fields do not require a bump.
//
// The host block, per-collector status and per-package source/ecosystem
// fields were all added without a bump: servers that predate them ignore
// unknown JSON fields, and newer servers detect them by presence. See
// docs/PROTOCOL.md.
const SchemaVersion = 1

type Snapshot struct {
	SchemaVersion int    `json:"schema_version"`
	CollectedAt   string `json:"collected_at"` // RFC3339

	// Host says which host this snapshot describes and what it is. It is
	// always present in snapshots from this agent version; older agents
	// omit it, which the server treats as the agent's local host.
	Host Host      `json:"host"`
	OS   OSRelease `json:"os"`

	// Collectors records the outcome of every collector for this push,
	// keyed by collector name (see the Collector* constants). It lets the
	// server tell "collected, and empty" from "not collected": a section
	// whose collector isn't StatusOK must never be treated as authoritative
	// (e.g. never close package ranges from a failed package collector).
	Collectors map[string]CollectorStatus `json:"collectors"`

	// Packages holds the installed packages from every package source whose
	// status is ok, each tagged with its ecosystem. It is null when no
	// source succeeded.
	Packages         []Package `json:"packages"`
	ListeningSockets []Socket  `json:"listening_sockets"`
	RebootRequired   bool      `json:"reboot_required"`
	RebootPackages   []string  `json:"reboot_required_packages,omitempty"`

	// PublicIPv4 / PublicIPv6 are the agent's own best-effort belief about
	// its public address(es), looked up via an outbound third-party call
	// (see CollectPublicIPs). Either may be empty when unavailable — this
	// is normal and never an error. Distinct from the server-observed
	// TCP/proxy source IP of the push connection (server-side clientIP()),
	// which serves a different, security-verification purpose.
	PublicIPv4 string `json:"public_ipv4,omitempty"`
	PublicIPv6 string `json:"public_ipv6,omitempty"`
}

// Host identifies the collected host (DOMAIN_MODEL.md §4.3–4.4).
type Host struct {
	Ref      string       `json:"ref"`       // "local", later a remote target name
	OSFamily string       `json:"os_family"` // "linux" | "windows" | "macos" | "" (undetected)
	Hostname string       `json:"hostname,omitempty"`
	Identity HostIdentity `json:"identity"`
}

// HostIdentity carries the stable machine identifiers the server keys hosts
// on. Only the Linux key exists today; Windows (machine_guid, smbios_uuid)
// and macOS (platform_uuid) keys are added alongside their collectors.
type HostIdentity struct {
	MachineID string `json:"machine_id,omitempty"`
}

type OSRelease struct {
	ID        string `json:"id"`         // e.g. "ubuntu", "debian"
	VersionID string `json:"version_id"` // e.g. "22.04", "12"
	Codename  string `json:"codename"`   // e.g. "jammy", "bookworm"
}

// Collector names used as keys in Snapshot.Collectors. Package sources add
// their own names (e.g. "deb_packages"; see pkgsource.Source.Name).
const (
	CollectorOS             = "os"
	CollectorHostIdentity   = "host_identity"
	CollectorTCPListeners   = "tcp_listeners"
	CollectorRebootRequired = "reboot_required"
	CollectorPublicIP       = "public_ip"
)

// Status values for CollectorStatus.Status.
const (
	StatusOK      = "ok"      // collected; the section is authoritative
	StatusError   = "error"   // applicable but failed; the section is unknown
	StatusSkipped = "skipped" // not applicable to this host; the section is absent
)

type CollectorStatus struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`  // set for StatusError
	Reason string `json:"reason,omitempty"` // set for StatusSkipped
}

func OK() CollectorStatus { return CollectorStatus{Status: StatusOK} }

func Failed(err error) CollectorStatus {
	return CollectorStatus{Status: StatusError, Error: err.Error()}
}

func Skipped(reason string) CollectorStatus {
	return CollectorStatus{Status: StatusSkipped, Reason: reason}
}

// Package is one installed package. Name/Version/Arch describe the binary
// package as installed; Source/SourceVersion the source package it was
// built from, which is what Debian/Ubuntu advisories are keyed by
// (DOMAIN_MODEL.md §2.5). Ecosystems without a source/binary split set
// Source = Name and SourceVersion = Version.
type Package struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Arch          string `json:"arch"`
	Source        string `json:"source"`
	SourceVersion string `json:"source_version"`
	Ecosystem     string `json:"ecosystem"` // e.g. "deb"; see pkgsource.Source.Ecosystem
}

// Socket describes one listening TCP socket found on the host, best-effort
// mapped to the owning process.
type Socket struct {
	Proto       string `json:"proto"` // "tcp" or "tcp6"
	LocalAddr   string `json:"local_addr"`
	Port        int    `json:"port"`
	PID         int    `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`

	// inode is used internally to match this socket to its owning process
	// via /proc/<pid>/fd; it is never serialized.
	inode int `json:"-"`
}
