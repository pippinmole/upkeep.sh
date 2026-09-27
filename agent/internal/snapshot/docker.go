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
	// ReasonSwarmLocked: the node's Swarm is locked (autolock, waiting for
	// "docker swarm unlock"), so it can't list services until unlocked.
	ReasonSwarmLocked = "swarm locked"
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

	// The other collectors run even if docker_engine failed (except
	// swarm_services, which needs its Swarm role): the engine answered
	// Open's ping, and their calls don't depend on /version or /info. Each
	// sets its own member of docker (nil when empty, like everywhere in
	// the snapshot) and its own status. Single-call collectors go first,
	// so the inspect fan-out of containers and images, the only part that
	// grows with the host, can't starve them of the Docker budget.
	if networks, truncated, err := collector.CollectDockerNetworks(ctx, cl); err != nil {
		status[collector.CollectorDockerNetworks] = collector.Failed(err)
	} else {
		if len(networks) > 0 {
			docker.Networks = networks
		}
		status[collector.CollectorDockerNetworks] = collector.OKTruncated(truncated)
	}

	// swarm_services needs the node's Swarm role from docker_engine.
	switch {
	case engineErr != nil:
		status[collector.CollectorSwarmServices] = collector.Skipped(ReasonDockerEngineUnavailable)
	case sw == nil:
		status[collector.CollectorSwarmServices] = collector.Skipped(ReasonNotInSwarm)
	case sw.State == collector.SwarmStateLocked:
		status[collector.CollectorSwarmServices] = collector.Skipped(ReasonSwarmLocked)
	case sw.Role != collector.SwarmRoleManager:
		status[collector.CollectorSwarmServices] = collector.Skipped(ReasonNotSwarmManager)
	default:
		services, truncated, err := collector.CollectSwarmServices(ctx, cl)
		switch {
		// Demoted, or left the Swarm, since /info: the node's state, not a
		// failure (see collector.ErrNotSwarmManager).
		case errors.Is(err, collector.ErrNotSwarmManager):
			status[collector.CollectorSwarmServices] = collector.Skipped(ReasonNotSwarmManager)
		case errors.Is(err, collector.ErrNotInSwarm):
			status[collector.CollectorSwarmServices] = collector.Skipped(ReasonNotInSwarm)
		case errors.Is(err, collector.ErrSwarmLocked):
			status[collector.CollectorSwarmServices] = collector.Skipped(ReasonSwarmLocked)
		case err != nil:
			status[collector.CollectorSwarmServices] = collector.Failed(err)
		default:
			if len(services) > 0 {
				docker.SwarmServices = services
			}
			status[collector.CollectorSwarmServices] = collector.OKTruncated(truncated)
		}
	}

	if containers, truncated, err := collector.CollectDockerContainers(ctx, cl); err != nil {
		status[collector.CollectorDockerContainers] = collector.Failed(err)
	} else {
		if len(containers) > 0 {
			docker.Containers = containers
		}
		status[collector.CollectorDockerContainers] = collector.OKTruncated(truncated)
	}
	if images, truncated, err := collector.CollectDockerImages(ctx, cl); err != nil {
		status[collector.CollectorDockerImages] = collector.Failed(err)
	} else {
		if len(images) > 0 {
			docker.Images = images
		}
		status[collector.CollectorDockerImages] = collector.OKTruncated(truncated)
	}

	if docker.Engine == nil && docker.Swarm == nil && docker.Containers == nil &&
		docker.Images == nil && docker.Networks == nil && docker.SwarmServices == nil {
		return nil
	}
	return docker
}
