// Package collector gathers read-only facts about the host: installed
// packages, listening sockets, OS release, and pending-reboot state.
// It never executes commands and never mutates host state.
package collector

// SchemaVersion is bumped whenever the Snapshot payload shape changes in a
// way the server needs to branch on. Additive fields do not require a bump.
const SchemaVersion = 1

type Snapshot struct {
	SchemaVersion    int        `json:"schema_version"`
	CollectedAt      string     `json:"collected_at"` // RFC3339
	OS               OSRelease  `json:"os"`
	Packages         []Package  `json:"packages"`
	ListeningSockets []Socket   `json:"listening_sockets"`
	RebootRequired   bool       `json:"reboot_required"`
	RebootPackages   []string   `json:"reboot_required_packages,omitempty"`
}

type OSRelease struct {
	ID        string `json:"id"`         // e.g. "ubuntu", "debian"
	VersionID string `json:"version_id"` // e.g. "22.04", "12"
	Codename  string `json:"codename"`   // e.g. "jammy", "bookworm"
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
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
