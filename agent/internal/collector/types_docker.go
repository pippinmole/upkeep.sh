package collector

import (
	"sort"
	"strings"
)

// Docker wire types (docs/PROTOCOL.md "Docker sections"). These structs
// ARE the field allowlist for everything read from the Docker Engine API:
// SDK structs are mapped onto them field by field and never sent as-is,
// so only what is declared here can leave the host. In particular there is
// deliberately no field for environment variables, command / entrypoint /
// args, Swarm secret or config references, volume names or driver
// options, mount sources other than bind host paths, or labels outside the
// allowlist (see FilterDockerLabels). Adding a field here is a privacy decision, not
// plumbing.
//
// Times are RFC3339 strings, like the rest of the payload. This package
// must not import any Docker SDK package; the mapping lives with the
// collectors.

// Docker payload size caps. A list that hits its cap is sorted by the key
// named on its constant and cut to the cap, and the owning collector's
// status is flagged truncated (CollectorStatus.Truncated), including when
// only a per-item list (a container's ports, an image's tags...) was cut:
// either way the server must read the section as additive only.
const (
	// Top-level lists, each sorted by id before cutting.
	MaxDockerContainers = 2000
	MaxDockerImages     = 2000
	MaxDockerNetworks   = 500
	MaxSwarmServices    = 1000

	// MaxDockerPortsPerContainer bounds DockerContainer.Ports, sorted by
	// (container_port, proto, host_ip, host_port). Published port ranges
	// ("8000-9000:8000-9000") expand to one entry per port, so this can
	// explode.
	MaxDockerPortsPerContainer = 100
	// MaxDockerMountsPerContainer bounds DockerContainer.Mounts, sorted by
	// destination.
	MaxDockerMountsPerContainer = 100
	// MaxDockerNetworksPerContainer bounds DockerContainer.Networks, sorted
	// by name.
	MaxDockerNetworksPerContainer = 50
	// MaxDockerRepoTagsPerImage / MaxDockerRepoDigestsPerImage bound
	// DockerImage.RepoTags / RepoDigests, each sorted lexically.
	MaxDockerRepoTagsPerImage    = 50
	MaxDockerRepoDigestsPerImage = 50
	// MaxDockerLayersPerImage bounds DockerImage.Layers. Layers are NOT
	// sorted: order is the layer chain (base first), so a cut keeps the
	// base-most layers. Docker's own overlay limit is ~125, so this should
	// never trigger on a real image.
	MaxDockerLayersPerImage = 256
	// MaxDockerSubnetsPerNetwork bounds DockerNetwork.Subnets, sorted
	// lexically.
	MaxDockerSubnetsPerNetwork = 20
	// MaxSwarmPortsPerService bounds SwarmService.Ports, sorted by
	// (target, proto, published, publish_mode).
	MaxSwarmPortsPerService = 100
	// MaxDockerLabels bounds the labels kept per object after filtering,
	// keeping the lexically first keys (enforced by FilterDockerLabels).
	// The org.opencontainers.image. prefix is open-ended, so an image can
	// declare arbitrarily many. Unlike the caps above, cutting labels does
	// not flag the collector truncated: labels are descriptive metadata on
	// an object that is itself fully reported, not an inventory.
	MaxDockerLabels = 64
)

// Docker is the snapshot's docker block. Each member is owned by one
// collector and omitted when that collector isn't ok; as everywhere in the
// snapshot, a member is authoritative iff its collector's status is ok,
// never by presence (an ok collector with nothing to report also omits
// its list).
type Docker struct {
	// Engine and Swarm are owned by "docker_engine". Swarm is omitted when
	// the engine is not part of a Swarm (or the node's Swarm state isn't
	// active).
	Engine *DockerEngine `json:"engine,omitempty"`
	Swarm  *DockerSwarm  `json:"swarm,omitempty"`

	Containers    []DockerContainer `json:"containers,omitempty"`     // "docker_containers"
	Images        []DockerImage     `json:"images,omitempty"`         // "docker_images"
	Networks      []DockerNetwork   `json:"networks,omitempty"`       // "docker_networks"
	SwarmServices []SwarmService    `json:"swarm_services,omitempty"` // "swarm_services", managers only
}

// DockerEngine describes the engine behind the socket (GET /version,
// GET /info).
type DockerEngine struct {
	Version    string `json:"version"`     // engine version, "29.8.0"
	APIVersion string `json:"api_version"` // engine's API version, "1.56"
	// StorageDriver is Info.Driver: the graphdriver ("overlay2") on the
	// classic image store, the snapshotter ("overlayfs") on the containerd
	// image store.
	StorageDriver string `json:"storage_driver,omitempty"`
	// ImageStore says which image store the engine uses: "containerd"
	// (the containerd snapshotter; Info.DriverStatus reports driver-type
	// io.containerd.snapshotter.v1) or "graphdriver" (classic). Omitted
	// when it can't be told (e.g. Podman). Image IDs and layer handling
	// differ between the two, so image matching needs to know.
	ImageStore string `json:"image_store,omitempty"`
	// Rootless: the daemon runs rootless (Info.SecurityOptions carries
	// "name=rootless").
	Rootless bool `json:"rootless"`
}

// DockerSwarm is this node's Swarm membership (Info.Swarm). The server
// joins nodes' task containers to managers' services by ClusterID /
// NodeID. Sent only for an active or locked node.
type DockerSwarm struct {
	// State is "active" or "locked". A locked node is a Swarm member whose
	// engine was restarted with autolock on and is waiting for
	// "docker swarm unlock": autolock only applies to managers, so it is in
	// practice a manager that can't act as one until unlocked. While
	// locked the Swarm node isn't running, so the engine reports no role
	// or cluster id (both absent) and, on current engines, no node id
	// (sent only if the engine gives one): the block then says only "this
	// node is in a Swarm, and locked".
	State     string `json:"state"`
	NodeID    string `json:"node_id,omitempty"`    // always set when active
	ClusterID string `json:"cluster_id,omitempty"` // only managers are told the cluster id
	Role      string `json:"role,omitempty"`       // "manager" | "worker"; always set when active
}

// DockerContainer is one container, running or not (list all=true, plus
// inspect for fields the list lacks).
type DockerContainer struct {
	ID   string `json:"id"`   // full 64-hex id
	Name string `json:"name"` // without the leading "/"
	// Image is the reference as configured (a tag can move); ImageID is
	// the image the container actually runs ("sha256:…"), the key for
	// image CVE matching.
	Image   string `json:"image"`
	ImageID string `json:"image_id"`
	// State is the engine's state: "created", "running", "paused",
	// "restarting", "removing", "exited" or "dead".
	State string `json:"state"`
	// StartedAt is the last start (RFC3339); omitted if never started.
	StartedAt string            `json:"started_at,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"` // FilterDockerLabels
	// Ports are the container's port bindings; capped at
	// MaxDockerPortsPerContainer.
	Ports []DockerPort `json:"ports,omitempty"`
	// Networks are the names of the networks the container is attached
	// to; capped at MaxDockerNetworksPerContainer.
	Networks []string `json:"networks,omitempty"`
	// NetworkMode is HostConfig.NetworkMode: "bridge", "host", "none",
	// "container:<id>" or a network name.
	NetworkMode string `json:"network_mode,omitempty"`
	Privileged  bool   `json:"privileged"`
	// RestartPolicy is HostConfig.RestartPolicy.Name: "no", "always",
	// "unless-stopped" or "on-failure".
	RestartPolicy string        `json:"restart_policy,omitempty"`
	Mounts        []DockerMount `json:"mounts,omitempty"` // capped at MaxDockerMountsPerContainer
}

// DockerPort is one container port binding. A port the image exposes but
// that isn't published has no host side: HostIP and HostPort are omitted.
type DockerPort struct {
	HostIP        string `json:"host_ip,omitempty"` // "0.0.0.0", "::", "127.0.0.1"
	HostPort      int    `json:"host_port,omitempty"`
	ContainerPort int    `json:"container_port"`
	Proto         string `json:"proto"` // "tcp" | "udp" | "sctp"
}

// DockerMount is one mount in a container.
type DockerMount struct {
	Type string `json:"type"` // "bind" | "volume" | "tmpfs" | "npipe" | "cluster" | "image"
	// Source is set ONLY for Type "bind", where it is a host path (the
	// dashboard flags e.g. the Docker socket or "/" bind-mounted into a
	// container). The mapping code must leave it empty for every other
	// type: a volume's name and driver options can carry credentials
	// (CIFS/NFS options), and the other types' sources are not host paths.
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination"`
	RW          bool   `json:"rw"`
}

// DockerImage is one local image (image list, plus inspect for os/arch and
// layers).
type DockerImage struct {
	ID          string            `json:"id"`                     // "sha256:…"
	RepoTags    []string          `json:"repo_tags,omitempty"`    // empty for dangling images
	RepoDigests []string          `json:"repo_digests,omitempty"` // "postgres@sha256:…"
	Created     string            `json:"created,omitempty"`      // RFC3339
	OS          string            `json:"os,omitempty"`           // "linux"
	Arch        string            `json:"arch,omitempty"`         // "amd64"
	Layers      []string          `json:"layers,omitempty"`       // RootFS.Layers diff IDs, base first
	Labels      map[string]string `json:"labels,omitempty"`       // FilterDockerLabels
}

// DockerNetwork is one network known to the engine.
type DockerNetwork struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Driver   string   `json:"driver"` // "bridge", "overlay", "host", "macvlan", "null"...
	Scope    string   `json:"scope"`  // "local" | "swarm" | "global"
	Internal bool     `json:"internal"`
	Subnets  []string `json:"subnets,omitempty"` // IPAM config CIDRs
}

// SwarmService is one Swarm service, reported by managers only. Never
// carries the task template's env, command, args, secrets or configs.
type SwarmService struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Image string `json:"image"` // "ghcr.io/me/api:1@sha256:…" as in the spec
	// Mode is "replicated", "global", "replicated-job" or "global-job".
	Mode string `json:"mode"`
	// Replicas is the configured replica count, sent only for mode
	// "replicated" (0 = scaled to zero). It is omitted for "global" (one
	// task per eligible node) and for both job modes: a job's target
	// (TotalCompletions / MaxConcurrent) is not sent at all.
	Replicas *int `json:"replicas,omitempty"`
	// RunningTasks / DesiredTasks are the engine's current task counts
	// (ServiceStatus): tasks in the running state, and tasks the
	// orchestrator wants running (the replica count for replicated
	// services, the eligible node count for global ones). They are the
	// current state and change as tasks restart or reschedule; the server
	// stores them as current values, not history. Both are absent when the
	// engine returns no ServiceStatus (it is only sent on request, since
	// API 1.41, so an engine that ignores the request), and present,
	// including 0, otherwise.
	RunningTasks *int              `json:"running_tasks,omitempty"`
	DesiredTasks *int              `json:"desired_tasks,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"` // FilterDockerLabels
	Ports        []SwarmPort       `json:"ports,omitempty"`  // capped at MaxSwarmPortsPerService
}

// SwarmPort is one port a service publishes (Endpoint.Ports).
type SwarmPort struct {
	Published   int    `json:"published,omitempty"` // omitted when the engine hasn't assigned one yet
	Target      int    `json:"target"`
	Proto       string `json:"proto"`        // "tcp" | "udp" | "sctp"
	PublishMode string `json:"publish_mode"` // "ingress" | "host"
}

// dockerLabelKeys are the exact Compose / stack / Swarm label keys ever
// sent: the ones those tools set themselves, each an identifier, digest,
// version, marker or (for the compose project.* keys) a host path. Sources:
// docker/compose pkg/api/labels.go, docker/cli cli/compose/convert
// (stack), moby daemon/cluster/executor/container (Swarm task system
// labels). Compose's network/volume labels are left out: they only appear
// on networks and volumes, which carry no labels on the wire.
var dockerLabelKeys = map[string]bool{
	// Docker Compose.
	"com.docker.compose.project":                  true,
	"com.docker.compose.service":                  true,
	"com.docker.compose.container-number":         true,
	"com.docker.compose.oneoff":                   true,
	"com.docker.compose.slug":                     true,
	"com.docker.compose.version":                  true,
	"com.docker.compose.config-hash":              true,
	"com.docker.compose.depends_on":               true, // "svc:condition:restart,…"
	"com.docker.compose.image":                    true, // image digest
	"com.docker.compose.image-volume-digest":      true,
	"com.docker.compose.image.builder":            true,
	"com.docker.compose.replace":                  true, // replaced container's name
	"com.docker.compose.engine":                   true,
	"com.docker.compose.hook":                     true,
	"com.docker.compose.relay":                    true,
	"com.docker.compose.project.config_files":     true, // host path(s)
	"com.docker.compose.project.working_dir":      true, // host path
	"com.docker.compose.project.environment_file": true, // host path only, never the file's content
	// docker stack deploy.
	"com.docker.stack.namespace": true,
	"com.docker.stack.image":     true,
	// Swarm task containers (system labels, set by the engine).
	"com.docker.swarm.node.id":      true,
	"com.docker.swarm.service.id":   true,
	"com.docker.swarm.service.name": true,
	"com.docker.swarm.task":         true,
	"com.docker.swarm.task.id":      true,
	"com.docker.swarm.task.name":    true,
}

// ociLabelPrefix is the one label namespace allowed as a prefix: the
// OCI image annotation keys (org.opencontainers.image.version, .source,
// .revision…), standardized and set at image build time.
const ociLabelPrefix = "org.opencontainers.image."

// FilterDockerLabels keeps only the allowlisted labels and returns nil
// when none survive: the exact Compose / stack / Swarm keys in
// dockerLabelKeys, plus any key under org.opencontainers.image.
//
// Labels are an allowlist, not a denylist, because they routinely carry
// secrets: reverse-proxy config lives in labels (Traefik basic-auth
// users/hashes, API keys in middleware headers), and so does arbitrary
// app config. Compose, stack and Swarm keys are matched exactly rather
// than by prefix because anyone can put a secret under a Docker-owned
// prefix in their own compose file (com.docker.compose.mytoken=…); only
// the keys those tools set themselves are known to be identifiers.
//
// At most MaxDockerLabels are kept, the lexically first keys, so the result
// is deterministic.
func FilterDockerLabels(labels map[string]string) map[string]string {
	var keys []string
	for k := range labels {
		if dockerLabelAllowed(k) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)
	if len(keys) > MaxDockerLabels {
		keys = keys[:MaxDockerLabels]
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		out[k] = labels[k]
	}
	return out
}

func dockerLabelAllowed(key string) bool {
	return dockerLabelKeys[key] ||
		(len(key) > len(ociLabelPrefix) && strings.HasPrefix(key, ociLabelPrefix))
}
