package collector

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/moby/moby/api/types/swarm"
	"github.com/moby/moby/api/types/system"
	"github.com/moby/moby/client"

	"github.com/pippinmole/upkeep.sh/agent/internal/dockerapi"
)

// DockerCallTimeout bounds each Docker Engine API call a collector makes.
// The snapshot bounds the whole Docker block separately.
const DockerCallTimeout = 10 * time.Second

// Swarm roles (DockerSwarm.Role).
const (
	SwarmRoleManager = "manager"
	SwarmRoleWorker  = "worker"
)

// containerdSnapshotterType is the "driver-type" DriverStatus value an
// engine using the containerd image store reports.
const containerdSnapshotterType = "io.containerd.snapshotter.v1"

// CollectDockerEngine describes the engine behind c (GET /version and
// GET /info) and, when the node is an active Swarm member, its Swarm
// membership. swarm is nil outside Swarm; later collectors use its Role to
// decide whether Swarm-manager-only calls apply.
//
// Both calls are required: if either fails the collector fails, rather
// than reporting an engine block with holes the server can't tell from
// real values.
func CollectDockerEngine(ctx context.Context, c dockerapi.Client) (DockerEngine, *DockerSwarm, error) {
	vctx, cancel := context.WithTimeout(ctx, DockerCallTimeout)
	ver, err := c.Version(vctx)
	cancel()
	if err != nil {
		return DockerEngine{}, nil, fmt.Errorf("docker version: %w", err)
	}
	ictx, cancel := context.WithTimeout(ctx, DockerCallTimeout)
	info, err := c.Info(ictx)
	cancel()
	if err != nil {
		return DockerEngine{}, nil, fmt.Errorf("docker info: %w", err)
	}
	return dockerEngine(ver, info), dockerSwarm(info.Swarm), nil
}

func dockerEngine(ver client.ServerVersionResult, info system.Info) DockerEngine {
	e := DockerEngine{
		// Version is the engine's own version. Info.ServerVersion carries
		// the same value; it is the fallback for an engine whose /version
		// leaves it empty.
		Version: ver.Version,
		// APIVersion is the highest API version the engine supports, as
		// its /version reports it (not the version the agent negotiated
		// down to for its own requests, which is min(engine, client) and
		// says nothing about the host).
		APIVersion:    ver.APIVersion,
		StorageDriver: info.Driver,
		ImageStore:    dockerImageStore(ver, info),
		Rootless:      slices.Contains(info.SecurityOptions, "name=rootless"),
	}
	if e.Version == "" {
		e.Version = info.ServerVersion
	}
	return e
}

// dockerImageStore tells the containerd image store from the classic
// graphdriver store. An engine on the containerd image store (the
// containerd snapshotter) reports exactly DriverStatus
// [["driver-type", "io.containerd.snapshotter.v1"]], and Driver is then
// the snapshotter name ("overlayfs"). On the classic store DriverStatus
// holds the graphdriver's own status ("Backing Filesystem", "Supports
// d_type"...) and no driver-type entry.
//
// The absence of that entry only means "graphdriver" on Docker Engine
// (moby) itself, which lists a component named "Engine" in /version.
// Other implementations of the API (Podman: "Podman Engine") have neither
// store, so the store is left empty there, as it is when the engine
// reports no storage driver at all.
func dockerImageStore(ver client.ServerVersionResult, info system.Info) string {
	for _, kv := range info.DriverStatus {
		if kv[0] == "driver-type" && kv[1] == containerdSnapshotterType {
			return "containerd"
		}
	}
	if info.Driver == "" {
		return ""
	}
	for _, comp := range ver.Components {
		if comp.Name == "Engine" {
			return "graphdriver"
		}
	}
	return ""
}

// dockerSwarm maps Info.Swarm. Only an active node is reported: inactive
// (not in a Swarm), pending (joining), locked (autolock, waiting for the
// unlock key) and error states have no usable membership, and a locked
// manager can't answer service lists either. An empty state (engines
// without Swarm, e.g. Podman) is not active either.
func dockerSwarm(s swarm.Info) *DockerSwarm {
	if s.LocalNodeState != swarm.LocalNodeStateActive || s.NodeID == "" {
		return nil
	}
	out := &DockerSwarm{NodeID: s.NodeID, Role: SwarmRoleWorker}
	if s.ControlAvailable {
		out.Role = SwarmRoleManager
	}
	// Only managers are told the cluster (Info.Swarm.Cluster is nil on
	// workers).
	if s.Cluster != nil {
		out.ClusterID = s.Cluster.ID
	}
	return out
}
