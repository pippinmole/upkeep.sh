package collector

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/moby/moby/api/types/swarm"

	"github.com/pippinmole/upkeep.sh/agent/internal/dockerapi"
)

// Swarm service modes (SwarmService.Mode).
const (
	SwarmModeReplicated    = "replicated"
	SwarmModeGlobal        = "global"
	SwarmModeReplicatedJob = "replicated-job"
	SwarmModeGlobalJob     = "global-job"
)

// ErrNotSwarmManager / ErrNotInSwarm mean the engine refused the service
// list because the node stopped being a manager (demoted) or left the Swarm
// between docker_engine's /info and the list call. They describe the
// node's state, not a failure, so the snapshot reports swarm_services
// skipped with the matching reason rather than as an error: an error would
// raise a "collector failing" alert on a healthy worker, and the next
// snapshot's docker_engine sees the new role and skips it anyway.
//
// ErrSwarmLocked is the same for a manager whose Swarm became locked
// (autolock, after an engine restart) in that window.
var (
	ErrNotSwarmManager = errors.New("not a swarm manager")
	ErrNotInSwarm      = errors.New("not in a swarm")
	ErrSwarmLocked     = errors.New("swarm locked")
)

// CollectSwarmServices lists the Swarm's services (GET /services,
// managers only) and maps each onto SwarmService. truncated is true when
// the service list or any service's ports hit their cap.
//
// Only the fields below are read from each service; the rest of the spec
// (the container spec's env, args, command, secrets, configs, mounts,
// privileges, and the update / rollback / placement config) is never
// touched. Of the status fields only ServiceStatus' running / desired
// counts are sent; JobStatus and UpdateStatus are not.
// Tasks and nodes are not listed: the wire type doesn't need them.
func CollectSwarmServices(ctx context.Context, c dockerapi.Client) (services []SwarmService, truncated bool, err error) {
	lctx, cancel := context.WithTimeout(ctx, DockerCallTimeout)
	list, err := c.ServiceList(lctx)
	cancel()
	if err != nil {
		return nil, false, swarmListError(err)
	}

	slices.SortFunc(list, func(a, b swarm.Service) int { return cmp.Compare(a.ID, b.ID) })
	if len(list) > MaxSwarmServices {
		list, truncated = list[:MaxSwarmServices], true
	}
	services = make([]SwarmService, 0, len(list))
	for _, s := range list {
		svc, portsCut := swarmService(s)
		truncated = truncated || portsCut
		services = append(services, svc)
	}
	return services, truncated, nil
}

// swarmListError recognises the engine's "this node is not a manager",
// "this node is not part of a swarm" and "swarm is locked" refusals
// (daemon/cluster errNoManager / errNoSwarm / errSwarmLocked; all 503
// Unavailable, like a leaderless manager, so the message is the only
// thing that tells them apart). Anything else, including a manager
// without quorum, is a real error.
func swarmListError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not a swarm manager"):
		return fmt.Errorf("docker service list: %w: %w", ErrNotSwarmManager, err)
	case strings.Contains(msg, "not part of a swarm"):
		return fmt.Errorf("docker service list: %w: %w", ErrNotInSwarm, err)
	// "Swarm is encrypted and needs to be unlocked before it can be used."
	case strings.Contains(msg, "needs to be unlocked"):
		return fmt.Errorf("docker service list: %w: %w", ErrSwarmLocked, err)
	}
	return fmt.Errorf("docker service list: %w", err)
}

// swarmService maps one service. portsCut reports a cut port list.
func swarmService(s swarm.Service) (svc SwarmService, portsCut bool) {
	svc = SwarmService{
		ID:     s.ID,
		Name:   s.Spec.Name,
		Labels: FilterDockerLabels(s.Spec.Labels),
	}
	// Image as configured in the spec, including a digest pin
	// ("img:tag@sha256:…"; docker stack deploy / service create pin it by
	// default). A plugin service (Runtime "plugin") has no container spec.
	if cs := s.Spec.TaskTemplate.ContainerSpec; cs != nil {
		svc.Image = cs.Image
	}
	svc.Mode, svc.Replicas = swarmMode(s.Spec.Mode)
	if st := s.ServiceStatus; st != nil {
		running, desired := int(st.RunningTasks), int(st.DesiredTasks)
		svc.RunningTasks, svc.DesiredTasks = &running, &desired
	}
	svc.Ports, portsCut = swarmPorts(s)
	return svc, portsCut
}

// swarmMode returns the service's mode and, for replicated services, the
// desired replica count. Jobs report no replicas: a replicated job's
// TotalCompletions / MaxConcurrent are a completion target and a
// concurrency limit, not a steady-state number of running tasks, and
// sending either as "replicas" would read as a service that should have
// that many tasks up. An unrecognised mode (a future engine) is sent as
// an empty mode rather than guessed.
func swarmMode(m swarm.ServiceMode) (string, *int) {
	switch {
	case m.Replicated != nil:
		// The engine always fills Replicas (swarmkit defaults it to 1);
		// if it ever doesn't, nothing is guessed.
		if m.Replicated.Replicas == nil {
			return SwarmModeReplicated, nil
		}
		n := int(*m.Replicated.Replicas)
		return SwarmModeReplicated, &n
	case m.Global != nil:
		return SwarmModeGlobal, nil
	case m.ReplicatedJob != nil:
		return SwarmModeReplicatedJob, nil
	case m.GlobalJob != nil:
		return SwarmModeGlobalJob, nil
	}
	return "", nil
}

// swarmPorts maps the service's published ports. Endpoint.Ports is what
// the Swarm allocator actually assigned: an ingress port given without a
// published port gets one from the 30000-32767 range there, while
// Spec.EndpointSpec only holds what the user asked for. Endpoint is empty
// until the allocator has processed the service (just created, or a
// manager that hasn't caught up), and then the spec's ports are the best
// available; their published port is 0 (omitted) when it was left to the
// allocator. A host-mode port without a published port gets a dynamic
// host port per task, so it stays 0 even in Endpoint.
//
// Protocol and publish mode default as swarmkit does when the spec leaves
// them empty: "tcp" and "ingress".
func swarmPorts(s swarm.Service) (ports []SwarmPort, cut bool) {
	src := s.Endpoint.Ports
	if len(src) == 0 && s.Spec.EndpointSpec != nil {
		src = s.Spec.EndpointSpec.Ports
	}
	if len(src) == 0 {
		return nil, false
	}
	ports = make([]SwarmPort, 0, len(src))
	for _, p := range src {
		sp := SwarmPort{
			Published:   int(p.PublishedPort),
			Target:      int(p.TargetPort),
			Proto:       strings.ToLower(string(p.Protocol)),
			PublishMode: string(p.PublishMode),
		}
		if sp.Proto == "" {
			sp.Proto = "tcp"
		}
		if sp.PublishMode == "" {
			sp.PublishMode = string(swarm.PortConfigPublishModeIngress)
		}
		ports = append(ports, sp)
	}
	slices.SortFunc(ports, func(a, b SwarmPort) int {
		return cmp.Or(
			cmp.Compare(a.Target, b.Target),
			cmp.Compare(a.Proto, b.Proto),
			cmp.Compare(a.Published, b.Published),
			cmp.Compare(a.PublishMode, b.PublishMode),
		)
	})
	if len(ports) > MaxSwarmPortsPerService {
		ports, cut = ports[:MaxSwarmPortsPerService], true
	}
	return ports, cut
}
