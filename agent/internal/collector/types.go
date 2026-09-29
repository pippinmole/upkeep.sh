// Package collector gathers read-only facts about a host: listening
// sockets, services, users, processes on deleted libraries, update
// settings, pending-reboot state and public IPs, and defines the snapshot
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

	// Agent describes the agent build that collected this snapshot (not the
	// host). Added without a schema bump; older agents omit it.
	Agent *Agent `json:"agent,omitempty"`

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
	// RebootSource says which signal reboot_required came from:
	// "flag_file" (/run/reboot-required was readable) or "kernel" (a newer
	// kernel than the running one is installed; also used when the flag
	// file isn't visible). Omitted when the collector isn't ok. Added
	// without a schema bump.
	RebootSource string `json:"reboot_required_source,omitempty"`

	// PublicIPv4 / PublicIPv6 are the agent's own best-effort belief about
	// its public address(es), looked up via an outbound third-party call
	// (see CollectPublicIPs). Either may be empty when unavailable — this
	// is normal and never an error. Distinct from the server-observed
	// TCP/proxy source IP of the push connection (server-side clientIP()),
	// which serves a different, security-verification purpose.
	PublicIPv4 string `json:"public_ipv4,omitempty"`
	PublicIPv6 string `json:"public_ipv6,omitempty"`

	// UptimeSeconds is whole seconds since the host booted (/proc/uptime),
	// owned by the "uptime" collector; omitted when it isn't ok.
	UptimeSeconds *int64 `json:"uptime_seconds,omitempty"`

	// Services is the host's service inventory (systemd units today),
	// owned by the "systemd_services" collector. Users is its local
	// accounts, owned by "local_users". Both are omitted when empty: a
	// section is authoritative iff its collector is ok, never by presence.
	Services []Service `json:"services,omitempty"`
	Users    []User    `json:"users,omitempty"`

	// Facts holds long-tail per-OS scalars and small lists that the server
	// stores as-is (snapshots.facts) rather than as range tables. Each
	// member is owned by its own collector and omitted when that isn't ok.
	Facts *Facts `json:"facts,omitempty"`

	// Docker is the Docker Engine inventory (types_docker.go), collected
	// only by a local agent with the Docker socket mounted. Each member is
	// owned by its own collector and omitted when that collector isn't ok:
	// engine and swarm by "docker_engine" (swarm also omitted outside
	// Swarm), containers by "docker_containers", images by
	// "docker_images", networks by "docker_networks", swarm_services by
	// "swarm_services" (managers only). The whole block is omitted when
	// no Docker collector is ok. Added without a schema bump.
	Docker *Docker `json:"docker,omitempty"`
}

// Agent is the snapshot's agent block. The server stores it on the agent
// row (agents.agent_version / platform / push_interval_seconds) and uses the
// interval to judge whether the agent is still active.
type Agent struct {
	Version         string `json:"version"`                    // build version, "dev" when unset
	Platform        string `json:"platform"`                   // runtime GOOS/GOARCH, "linux/amd64"
	IntervalSeconds int    `json:"interval_seconds,omitempty"` // push interval (SW_INTERVAL)
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
	// Kernel is the running kernel release ("6.8.0-45-generic"), owned by
	// the "kernel" collector; omitted when that collector isn't ok. Added
	// without a schema bump (servers that predate it ignore it).
	Kernel string `json:"kernel,omitempty"`
	// Arch is the host's native architecture in Debian naming ("amd64",
	// "arm64"), owned by the "arch" collector; omitted when it isn't ok.
	// See CollectArch for where it comes from.
	Arch string `json:"arch,omitempty"`
}

// Collector names used as keys in Snapshot.Collectors. Package sources add
// their own names (e.g. "deb_packages"; see pkgsource.Source.Name).
const (
	CollectorOS             = "os"
	CollectorKernel         = "kernel"
	CollectorHostIdentity   = "host_identity"
	CollectorTCPListeners   = "tcp_listeners"
	CollectorRebootRequired = "reboot_required"
	CollectorPublicIP       = "public_ip"

	CollectorUptime             = "uptime"
	CollectorArch               = "arch"
	CollectorUDPListeners       = "udp_listeners"
	CollectorSystemdServices    = "systemd_services"
	CollectorLocalUsers         = "local_users"
	CollectorDeletedLibs        = "deleted_libs"
	CollectorUnattendedUpgrades = "unattended_upgrades"

	// CollectorHostMount is the agent's own deployment check, not a host
	// fact: ok when no host unix socket is reachable under the host root
	// (target.Local.ReachableSockets), error listing them otherwise,
	// skipped on remote targets and bare metal. It owns no section.
	CollectorHostMount = "host_mount"

	// Docker collectors (local targets with the socket mounted; skipped
	// with a reason otherwise). docker_engine owns docker.engine and
	// docker.swarm.
	CollectorDockerEngine     = "docker_engine"
	CollectorDockerContainers = "docker_containers"
	CollectorDockerImages     = "docker_images"
	CollectorDockerNetworks   = "docker_networks"
	CollectorSwarmServices    = "swarm_services"
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
	// Truncated (with StatusOK) means the section hit its size cap and
	// holds only a deterministic prefix (sorted by key) of what exists.
	// The server must then treat it as additive only: nothing missing from
	// a truncated list may be read as removed.
	Truncated bool `json:"truncated,omitempty"`
}

// OKTruncated is OK, flagged truncated when truncated is true.
func OKTruncated(truncated bool) CollectorStatus {
	return CollectorStatus{Status: StatusOK, Truncated: truncated}
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

// Socket describes one listening socket found on the host, best-effort
// mapped to the owning process. TCP sockets are those in LISTEN state; UDP
// sockets are bound and unconnected (see parseProcNet).
type Socket struct {
	Proto       string `json:"proto"` // "tcp", "tcp6", "udp" or "udp6"
	LocalAddr   string `json:"local_addr"`
	Port        int    `json:"port"`
	PID         int    `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`

	// inode is used internally to match this socket to its owning process
	// via /proc/<pid>/fd; it is never serialized.
	inode int `json:"-"`
}
