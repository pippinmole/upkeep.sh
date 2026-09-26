package ingest

// SnapshotPayload mirrors agent/internal/collector.Snapshot. The two are
// kept as independent types (not a shared Go module) because the wire
// format is the actual contract — schema_version is what lets the server
// evolve independently of already-deployed agents. Keep this in sync with
// the agent's collector.Snapshot; a mismatch should only ever be additive
// fields, gated by schema_version.
type SnapshotPayload struct {
	SchemaVersion    int              `json:"schema_version"`
	CollectedAt      string           `json:"collected_at"`
	OS               OSRelease        `json:"os"`
	Packages         []Package        `json:"packages"`
	ListeningSockets []Socket         `json:"listening_sockets"`
	RebootRequired   bool             `json:"reboot_required"`
	RebootPackages   []string         `json:"reboot_required_packages,omitempty"`
}

type OSRelease struct {
	ID        string `json:"id"`
	VersionID string `json:"version_id"`
	Codename  string `json:"codename"`
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
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
