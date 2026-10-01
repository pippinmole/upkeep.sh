package ingest

import "encoding/json"

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

	// Added within schema_version 1 for the Linux breadth collectors; each
	// section is authoritative only when its collector reported ok (see
	// planFacts). Older agents omit them all.
	UptimeSeconds *int64    `json:"uptime_seconds,omitempty"`
	Services      []Service `json:"services,omitempty"`
	Users         []User    `json:"users,omitempty"`
	// Facts is validated separately (hostfacts.ValidateLinuxFacts), so a
	// malformed block drops the facts, not the push.
	Facts json.RawMessage `json:"facts,omitempty"`
	// Docker is decoded separately into Docker (decodeDocker), so a
	// malformed block drops the Docker sections, not the push.
	Docker json.RawMessage `json:"docker,omitempty"`
}

type OSRelease struct {
	ID        string `json:"id"`
	VersionID string `json:"version_id"`
	Codename  string `json:"codename"`
	// Kernel is the running kernel release (/proc/sys/kernel/osrelease,
	// what `uname -r` prints), owned by the "kernel" collector. Added
	// within schema_version 1; older agents omit it.
	Kernel string `json:"kernel,omitempty"`
	// Arch is the host architecture in Debian naming ("amd64"), owned by
	// the "arch" collector. Added within schema_version 1.
	Arch string `json:"arch,omitempty"`
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
	// Truncated: the section hit the agent's size cap and lists only a
	// prefix; it may open ranges but must never close any.
	Truncated bool `json:"truncated,omitempty"`
}

const (
	CollectorStatusOK = "ok"
	CollectorOS       = "os"
	CollectorKernel   = "kernel"

	CollectorHostIdentity = "host_identity"

	CollectorTCPListeners       = "tcp_listeners"
	CollectorUDPListeners       = "udp_listeners"
	CollectorUptime             = "uptime"
	CollectorArch               = "arch"
	CollectorSystemdServices    = "systemd_services"
	CollectorLocalUsers         = "local_users"
	CollectorDeletedLibs        = "deleted_libs"
	CollectorUnattendedUpgrades = "unattended_upgrades"

	// Docker (PROTOCOL.md "Docker sections"). Each owns one member of the
	// docker block.
	CollectorDockerEngine     = "docker_engine" // engine, swarm
	CollectorDockerContainers = "docker_containers"
	CollectorDockerImages     = "docker_images"
	CollectorDockerNetworks   = "docker_networks"
	CollectorSwarmServices    = "swarm_services"
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

// Service mirrors the agent's collector.Service.
type Service struct {
	Manager     string         `json:"manager"`
	Name        string         `json:"name"`
	DisplayName string         `json:"display_name,omitempty"`
	StartMode   string         `json:"start_mode"`
	State       string         `json:"state,omitempty"`
	RunAs       string         `json:"run_as,omitempty"`
	BinaryPath  string         `json:"binary_path,omitempty"`
	Attrs       map[string]any `json:"attrs,omitempty"`
}

// User mirrors the agent's collector.User.
type User struct {
	Name       string   `json:"name"`
	UID        int64    `json:"uid"`
	GID        int64    `json:"gid"`
	Home       string   `json:"home,omitempty"`
	Shell      string   `json:"shell,omitempty"`
	Groups     []string `json:"groups,omitempty"`
	LoginShell bool     `json:"login_shell"`
	Admin      bool     `json:"admin"`
}

// Docker mirrors the agent's collector.Docker (types_docker.go). Only the
// declared fields are read; anything else in the block is ignored.
type Docker struct {
	Engine        *DockerEngine     `json:"engine"`
	Swarm         *DockerSwarm      `json:"swarm"`
	Containers    []DockerContainer `json:"containers"`
	Images        []DockerImage     `json:"images"`
	Networks      []DockerNetwork   `json:"networks"`
	SwarmServices []SwarmService    `json:"swarm_services"`
}

type DockerEngine struct {
	Version       string `json:"version"`
	APIVersion    string `json:"api_version"`
	StorageDriver string `json:"storage_driver"`
	ImageStore    string `json:"image_store"`
	Rootless      bool   `json:"rootless"`
}

type DockerSwarm struct {
	State     string `json:"state"` // "active" | "locked"
	NodeID    string `json:"node_id"`
	ClusterID string `json:"cluster_id"` // managers only
	Role      string `json:"role"`       // "manager" | "worker"
}

type DockerContainer struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Image         string            `json:"image"`
	ImageID       string            `json:"image_id"`
	State         string            `json:"state"`
	StartedAt     string            `json:"started_at"`
	Labels        map[string]string `json:"labels"`
	Ports         []DockerPort      `json:"ports"`
	Networks      []string          `json:"networks"`
	NetworkMode   string            `json:"network_mode"`
	Privileged    *bool             `json:"privileged"`
	RestartPolicy string            `json:"restart_policy"`
	Mounts        []DockerMount     `json:"mounts"`
	// InspectError marks a partial entry: only ID, Name, Image, ImageID,
	// State and Labels are known.
	InspectError string `json:"inspect_error"`
}

type DockerPort struct {
	HostIP        string `json:"host_ip"`
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Proto         string `json:"proto"`
}

type DockerMount struct {
	Type        string `json:"type"`
	Source      string `json:"source"` // bind mounts only
	Destination string `json:"destination"`
	RW          bool   `json:"rw"`
}

type DockerImage struct {
	ID          string            `json:"id"`
	RepoTags    []string          `json:"repo_tags"`
	RepoDigests []string          `json:"repo_digests"`
	Created     string            `json:"created"`
	OS          string            `json:"os"`
	Arch        string            `json:"arch"`
	Variant     string            `json:"variant"`
	Layers      []string          `json:"layers"`
	Labels      map[string]string `json:"labels"`
	// InspectError marks a partial entry: OS, Arch, Variant and Layers are
	// unknown.
	InspectError string `json:"inspect_error"`
}

type DockerNetwork struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Driver   string   `json:"driver"`
	Scope    string   `json:"scope"`
	Internal bool     `json:"internal"`
	Subnets  []string `json:"subnets"`
}

type SwarmService struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Image        string            `json:"image"`
	Mode         string            `json:"mode"`
	Replicas     *int              `json:"replicas"`
	RunningTasks *int              `json:"running_tasks"`
	DesiredTasks *int              `json:"desired_tasks"`
	Labels       map[string]string `json:"labels"`
	Ports        []SwarmPort       `json:"ports"`
}

type SwarmPort struct {
	Published   int    `json:"published"`
	Target      int    `json:"target"`
	Proto       string `json:"proto"`
	PublishMode string `json:"publish_mode"`
}

// MinSupportedSchemaVersion is the oldest agent payload shape this server
// still accepts. Bump only alongside a documented breaking change.
const (
	MinSupportedSchemaVersion = 1
	CurrentSchemaVersion      = 1
)
