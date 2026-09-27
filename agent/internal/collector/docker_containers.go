package collector

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"

	"github.com/pippinmole/upkeep.sh/agent/internal/dockerapi"
)

// CollectDockerContainers lists every container, running or not (GET
// /containers/json?all=1), inspects each one and maps it onto
// DockerContainer. truncated is true when the container list or any
// container's ports, mounts or networks hit their cap.
//
// The list only enumerates: containers are sorted by id and cut to
// MaxDockerContainers before any inspect, so a host over the cap costs no
// more than one at it. Everything sent comes from the inspect, the newer
// view, so state and started_at always describe the same moment. A
// container removed between the list and its inspect is skipped (it's
// gone); any other inspect failure fails the collector, see
// dockerInspectAll.
//
// Only the fields below are read. Config's Env, Cmd, Entrypoint, and the
// inspect's Path / Args are never touched; from Config only Image and
// Labels (through FilterDockerLabels).
func CollectDockerContainers(ctx context.Context, c dockerapi.Client) (containers []DockerContainer, truncated bool, err error) {
	lctx, cancel := context.WithTimeout(ctx, DockerCallTimeout)
	list, err := c.ContainerList(lctx)
	cancel()
	if err != nil {
		return nil, false, fmt.Errorf("docker container list: %w", err)
	}

	slices.SortFunc(list, func(a, b container.Summary) int { return cmp.Compare(a.ID, b.ID) })
	list = slices.CompactFunc(list, func(a, b container.Summary) bool { return a.ID == b.ID })
	if len(list) > MaxDockerContainers {
		list, truncated = list[:MaxDockerContainers], true
	}
	ids := make([]string, len(list))
	for i, s := range list {
		ids[i] = s.ID
	}
	inspects, found, err := dockerInspectAll(ctx, "container", ids, c.ContainerInspect)
	if err != nil {
		return nil, false, err
	}

	containers = make([]DockerContainer, 0, len(list))
	for i, s := range list {
		if !found[i] {
			continue
		}
		ctr, cut := dockerContainer(s, inspects[i])
		truncated = truncated || cut
		containers = append(containers, ctr)
	}
	return containers, truncated, nil
}

// dockerContainer maps one inspected container. s (its list entry) is only
// a fallback for the identity fields, should an engine leave them out of
// the inspect.
func dockerContainer(s container.Summary, in container.InspectResponse) (DockerContainer, bool) {
	out := DockerContainer{
		ID:      cmp.Or(in.ID, s.ID),
		Name:    strings.TrimPrefix(in.Name, "/"),
		Image:   s.Image,
		ImageID: cmp.Or(in.Image, s.ImageID),
		State:   string(s.State),
	}
	if out.Name == "" && len(s.Names) > 0 {
		out.Name = strings.TrimPrefix(s.Names[0], "/")
	}
	if in.Config != nil {
		out.Image = cmp.Or(in.Config.Image, out.Image)
		out.Labels = FilterDockerLabels(in.Config.Labels)
	} else {
		out.Labels = FilterDockerLabels(s.Labels)
	}
	if in.State != nil {
		out.State = cmp.Or(string(in.State.Status), out.State)
		out.StartedAt = dockerTime(in.State.StartedAt)
	}
	if in.HostConfig != nil {
		out.NetworkMode = string(in.HostConfig.NetworkMode)
		out.Privileged = in.HostConfig.Privileged
		out.RestartPolicy = string(in.HostConfig.RestartPolicy.Name)
	}

	var portsCut, netsCut, mountsCut bool
	if in.NetworkSettings != nil {
		out.Ports, portsCut = dockerPorts(in.NetworkSettings.Ports)
		out.Networks, netsCut = dockerNetworkNames(in.NetworkSettings.Networks)
	}
	out.Mounts, mountsCut = dockerMounts(in.Mounts)
	return out, portsCut || netsCut || mountsCut
}

// dockerPorts maps NetworkSettings.Ports: the container's current port
// map, one key per port the container exposes, with the host bindings
// published for it (none for an exposed-only port, which then has no host
// side). It is empty for a container that isn't running: nothing is
// published then.
//
// Identical entries are reported once: they carry no information, and the
// server keys ports on all four fields. IPv4 and IPv6 bindings of the same
// port ("0.0.0.0" and "::") are different entries.
func dockerPorts(pm network.PortMap) ([]DockerPort, bool) {
	var out []DockerPort
	for p, bindings := range pm {
		base := DockerPort{ContainerPort: int(p.Num()), Proto: string(p.Proto())}
		if len(bindings) == 0 {
			out = append(out, base)
			continue
		}
		for _, b := range bindings {
			dp := base
			if b.HostIP.IsValid() {
				dp.HostIP = b.HostIP.String()
			}
			// HostPort is a string; one the engine hasn't assigned (or
			// sent unparsable) leaves the host port out.
			if n, err := strconv.Atoi(b.HostPort); err == nil && n > 0 {
				dp.HostPort = n
			}
			out = append(out, dp)
		}
	}
	slices.SortFunc(out, compareDockerPorts)
	out = slices.Compact(out)
	return capList(out, MaxDockerPortsPerContainer)
}

func compareDockerPorts(a, b DockerPort) int {
	return cmp.Or(
		cmp.Compare(a.ContainerPort, b.ContainerPort),
		cmp.Compare(a.Proto, b.Proto),
		cmp.Compare(a.HostIP, b.HostIP),
		cmp.Compare(a.HostPort, b.HostPort),
	)
}

// dockerNetworkNames returns the names of the networks the container is
// attached to, sorted.
func dockerNetworkNames[V any](nets map[string]V) ([]string, bool) {
	var out []string
	for name := range nets {
		out = append(out, name)
	}
	slices.Sort(out)
	return capList(out, MaxDockerNetworksPerContainer)
}

// dockerMounts maps the container's mounts, sorted by destination. Source
// is copied only for bind mounts, where it is a host path; for every other
// type it is left empty (see DockerMount.Source): a volume's source is its
// directory under /var/lib/docker/volumes and its name can carry more than
// a name, and the other types' sources aren't host paths.
func dockerMounts(mounts []container.MountPoint) ([]DockerMount, bool) {
	var out []DockerMount
	for _, m := range mounts {
		dm := DockerMount{Type: string(m.Type), Destination: m.Destination, RW: m.RW}
		if m.Type == mount.TypeBind {
			dm.Source = m.Source
		}
		out = append(out, dm)
	}
	slices.SortFunc(out, func(a, b DockerMount) int {
		return cmp.Or(
			cmp.Compare(a.Destination, b.Destination),
			cmp.Compare(a.Type, b.Type),
			cmp.Compare(a.Source, b.Source),
		)
	})
	return capList(out, MaxDockerMountsPerContainer)
}

// dockerTime normalizes an engine timestamp (RFC3339 with nanoseconds) to
// RFC3339 UTC. The engine's zero time ("0001-01-01T00:00:00Z": a container
// never started, an image without a creation time) and anything
// unparsable come back empty, so the field is omitted. The Unix epoch is
// kept: reproducible builds date their images 1970-01-01 on purpose.
func dockerTime(s string) string {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// capList cuts a sorted list to max, reporting whether it did.
func capList[T any](s []T, max int) ([]T, bool) {
	if len(s) > max {
		return s[:max], true
	}
	return s, false
}
