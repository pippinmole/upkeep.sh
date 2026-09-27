package snapshot

import (
	"context"
	"errors"
	"time"

	"github.com/pippinmole/upkeep.sh/agent/internal/collector"
	"github.com/pippinmole/upkeep.sh/agent/internal/dockerapi"
	"github.com/pippinmole/upkeep.sh/agent/internal/target"
)

// Docker collector status reasons. The dashboard keys on these exact
// strings to tell its empty states apart (TASKS.md Phase 1.6), so they are
// part of the protocol: don't reword them.
const (
	// ReasonRemoteHost: the target is collected over SSH, whose read-only
	// SFTP access can't reach the target's Docker socket.
	ReasonRemoteHost = "remote host"
	// ReasonDockerSocketNotMounted: Docker collection isn't enabled on
	// this agent (nothing at SW_DOCKER_SOCKET), or the host has no Docker.
	ReasonDockerSocketNotMounted = "docker socket not mounted"
	// ReasonDockerEngineUnavailable: something is at the socket but the
	// engine couldn't be used (docker_engine carries the error). Reported
	// on the collectors that depend on the engine.
	ReasonDockerEngineUnavailable = "docker engine unavailable"
	// ReasonNotInSwarm / ReasonNotSwarmManager: swarm_services only runs
	// on Swarm managers.
	ReasonNotInSwarm      = "not in a swarm"
	ReasonNotSwarmManager = "not a swarm manager"
)

const (
	// dockerTimeout bounds the whole Docker block of one snapshot.
	dockerTimeout = 30 * time.Second
	// dockerOpenTimeout bounds connecting and the version handshake.
	dockerOpenTimeout = 10 * time.Second
)

// dockerCollectors is every Docker collector. Each one gets a status in
// every snapshot branch where Docker isn't reachable at all.
var dockerCollectors = []string{
	collector.CollectorDockerEngine,
	collector.CollectorDockerContainers,
	collector.CollectorDockerImages,
	collector.CollectorDockerNetworks,
	collector.CollectorSwarmServices,
}

// collectDocker runs the Docker collectors against the local target's
// engine, records their statuses and returns the docker block (nil when no
// Docker collector produced anything).
//
// The target mode is checked before anything else: a remote target never
// causes the socket to be stat'ed or dialed, whatever DockerSocket says.
func (c *Collector) collectDocker(ctx context.Context, t target.Target, isLinux bool, notLinux collector.CollectorStatus, status map[string]collector.CollectorStatus) *collector.Docker {
	skipAll := func(st collector.CollectorStatus) {
		for _, name := range dockerCollectors {
			status[name] = st
		}
	}
	switch {
	case t.Mode() != target.ModeLocal:
		skipAll(collector.Skipped(ReasonRemoteHost))
		return nil
	case !isLinux:
		skipAll(notLinux)
		return nil
	case c.OpenDocker == nil || c.DockerSocket == "":
		skipAll(collector.Skipped(ReasonDockerSocketNotMounted))
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()

	openCtx, openCancel := context.WithTimeout(ctx, dockerOpenTimeout)
	cl, err := c.OpenDocker(openCtx, c.DockerSocket)
	openCancel()
	switch {
	case errors.Is(err, dockerapi.ErrSocketNotMounted):
		skipAll(collector.Skipped(ReasonDockerSocketNotMounted))
		return nil
	case err != nil:
		// Unreachable, permission denied, too old: the one error is
		// reported on docker_engine. The dependents didn't run, so they're
		// skipped rather than repeating the same error four times; either
		// way the server never reads their sections as authoritative.
		skipAll(collector.Skipped(ReasonDockerEngineUnavailable))
		status[collector.CollectorDockerEngine] = collector.Failed(err)
		return nil
	}
	defer cl.Close()

	docker := &collector.Docker{}

	engine, sw, engineErr := collector.CollectDockerEngine(ctx, cl)
	if engineErr != nil {
		status[collector.CollectorDockerEngine] = collector.Failed(engineErr)
	} else {
		docker.Engine, docker.Swarm = &engine, sw
		status[collector.CollectorDockerEngine] = collector.OK()
	}

	// Collectors that only need a reachable engine plug in here, each
	// setting its own member of docker and its own status from cl (with
	// collector.DockerCallTimeout per call). They run even if
	// docker_engine failed: the engine answered Open's ping, and their
	// calls don't depend on /version or /info.
	//
	// Not built yet, so absent from the status map (like a collector an
	// older agent doesn't have): docker_containers, docker_images,
	// docker_networks.

	// swarm_services needs the node's Swarm role from docker_engine.
	switch {
	case engineErr != nil:
		status[collector.CollectorSwarmServices] = collector.Skipped(ReasonDockerEngineUnavailable)
	case sw == nil:
		status[collector.CollectorSwarmServices] = collector.Skipped(ReasonNotInSwarm)
	case sw.Role != collector.SwarmRoleManager:
		status[collector.CollectorSwarmServices] = collector.Skipped(ReasonNotSwarmManager)
	default:
		// Manager: the swarm_services collector plugs in here. Not built
		// yet, so absent from the status map.
	}

	if docker.Engine == nil && docker.Swarm == nil && docker.Containers == nil &&
		docker.Images == nil && docker.Networks == nil && docker.SwarmServices == nil {
		return nil
	}
	return docker
}
