package ingest

// SnapshotPayload mirrors agent/internal/collector.Snapshot. The two are
// kept as independent types (not a shared Go module) because the wire
// format is the actual contract — schema_version is what lets the server
// evolve independently of already-deployed agents. Keep this in sync with
// the agent's collector.Snapshot; a mismatch should only ever be additive
// fields, gated by schema_version.
type SnapshotPayload struct {
	SchemaVersion int    `json:"schema_version"`
	CollectedAt   string `json:"collected_at"`
	// Agent describes the pushing agent build; nil for older agents.
	Agent *Agent `json:"agent"`
	// Host is nil for agents that predate the host block: the push is for
	// the authenticating agent's local host.
	Host *Host     `json:"host"`
	OS   OSRelease `json:"os"`

	// Collectors is nil for agents that predate per-collector status; see
	// planInventory for how such payloads are interpreted.
	Collectors map[string]CollectorStatus `json:"collectors"`

	// Packages is nil when the field is absent or null (no package source
	// succeeded), and a non-nil empty slice for `[]`. The distinction
	// matters: only the latter can be an authoritative "nothing installed".
	Packages         []Package `json:"packages"`
	ListeningSockets []Socket  `json:"listening_sockets"`
	RebootRequired   bool      `json:"reboot_required"`
	RebootPackages   []string  `json:"reboot_required_packages,omitempty"`

	// PublicIPv4 / PublicIPv6 are agent-self-reported, best-effort values —
	// distinct from the server-observed source_ip (see clientIP() in
	// handler.go). Either may be empty/absent.
	PublicIPv4 string `json:"public_ipv4,omitempty"`
	PublicIPv6 string `json:"public_ipv6,omitempty"`
}

type OSRelease struct {
	ID        string `json:"id"`
	VersionID string `json:"version_id"`
	Codename  string `json:"codename"`
	// Kernel is the running kernel release (/proc/sys/kernel/osrelease,
	// what `uname -r` prints), owned by the "kernel" collector. Added
	// within schema_version 1; older agents omit it.
	Kernel string `json:"kernel,omitempty"`
}

// Agent is the snapshot's agent block (added within schema_version 1).
type Agent struct {
	Version         string `json:"version"`          // agent build version
	Platform        string `json:"platform"`         // GOOS/GOARCH of the agent binary, "linux/amd64"
	IntervalSeconds int    `json:"interval_seconds"` // the agent's push interval
}

// Host is the snapshot's host block (added within schema_version 1). The
// server resolves the host from it (store.resolveHost): ref "local" is the
// agent's own machine, identity.machine_id is the key hosts are upserted on.
type Host struct {
	Ref      string       `json:"ref"`
	OSFamily string       `json:"os_family"`
	Hostname string       `json:"hostname"`
	Identity HostIdentity `json:"identity"`
}

type HostIdentity struct {
	MachineID string `json:"machine_id"`
}

// CollectorStatus is one entry of the collectors map.
type CollectorStatus struct {
	Status string `json:"status"` // "ok" | "error" | "skipped"
	Error  string `json:"error,omitempty"`
	Reason string `json:"reason,omitempty"`
}

const (
	CollectorStatusOK = "ok"
	CollectorOS       = "os"
	CollectorKernel   = "kernel"

	CollectorHostIdentity = "host_identity"
)

// Package is one installed package. Source, SourceVersion and Ecosystem
// were added within schema_version 1; older agents omit them (see
// defaultPackage).
type Package struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Arch          string `json:"arch"`
	Source        string `json:"source,omitempty"`
	SourceVersion string `json:"source_version,omitempty"`
	Ecosystem     string `json:"ecosystem,omitempty"`
}

type Socket struct {
	Proto       string `json:"proto"`
	LocalAddr   string `json:"local_addr"`
	Port        int    `json:"port"`
	PID         int    `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
}

// MinSupportedSchemaVersion is the oldest agent payload shape this server
// still accepts. Bump only alongside a documented breaking change.
const MinSupportedSchemaVersion = 1
const CurrentSchemaVersion = 1
