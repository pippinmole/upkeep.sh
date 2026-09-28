package ingest

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/hostfacts"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

// Server-side caps for the Docker sections: above the agent's own
// (types_docker.go), which are the real limit, so they only bound what a
// misbehaving agent can store. Hitting a list cap makes the set additive,
// like the agent's truncated flag.
const (
	maxDockerContainers       = 5000
	maxDockerImages           = 5000
	maxDockerNetworks         = 1000
	maxSwarmServices          = 2000
	maxDockerPortsPerItem     = 200
	maxDockerMountsPerItem    = 200
	maxDockerNetworksPerItem  = 100
	maxDockerRefsPerImage     = 100
	maxDockerLayersPerImage   = 512
	maxDockerSubnetsPerNet    = 50
	maxDockerInspectErrorSize = 256
)

// Fact kinds (host_fact_state.kind) and the swarm_services set's kind.
const (
	KindDockerContainers = store.FactKindDockerContainers
	KindDockerImages     = store.FactKindDockerImages
	KindSwarmServices    = "services:swarm"
)

// dockerPlan is what one payload's docker block contributes to the
// snapshot. Every member comes from a collector that reported ok; the rest
// is left untouched in the database.
type dockerPlan struct {
	sets     []hostfacts.Set // containers:docker, images:docker
	images   []store.ContainerImage
	engine   *store.DockerEngineInput
	networks *store.DockerNetworksInput
	swarm    *store.SwarmServicesInput
	notes    []string
}

// planDocker applies the same authority rule as planFacts, per Docker
// collector (docs/PROTOCOL.md "collectors", "Docker sections"):
//
//   - a section is applied iff its collector reported ok, even when its
//     list is empty or absent (ok and empty closes every open range);
//     error / skipped ("remote host", "docker socket not mounted", …) /
//     missing leaves what is stored exactly as it is. Payloads without a
//     collectors map never carried Docker data, so nothing is applied.
//   - ok but truncated (or over a server cap): additive, never closing.
//   - a partial entry (inspect_error) keeps its range open and keeps the
//     detail its previous range had (store.reconcileRanges).
//   - swarm_services only from a manager: docker_engine must be ok too and
//     report an active Swarm with role manager and a cluster id (workers
//     are never told it). Anything else ignores the services.
func planDocker(p SnapshotPayload) dockerPlan {
	var plan dockerPlan
	if p.Collectors == nil {
		return plan
	}
	// An ok collector with nothing to report omits its member (and a host
	// with nothing at all may omit the block): absent reads as empty.
	var d Docker
	if len(p.Docker) > 0 && string(p.Docker) != "null" {
		if err := json.Unmarshal(p.Docker, &d); err != nil {
			plan.notes = append(plan.notes, fmt.Sprintf("docker block dropped: %v", err))
			return plan
		}
	}

	engineOK := collectorStatusOK(p, CollectorDockerEngine)
	if engineOK && d.Engine != nil {
		plan.engine = dockerEngine(d.Engine, d.Swarm)
	}
	if collectorStatusOK(p, CollectorDockerContainers) {
		plan.sets = append(plan.sets, containersSet(d.Containers, collectorTruncated(p, CollectorDockerContainers)))
	}
	if collectorStatusOK(p, CollectorDockerImages) {
		set, content := imagesSet(d.Images, collectorTruncated(p, CollectorDockerImages))
		plan.sets = append(plan.sets, set)
		plan.images = content
	}
	if collectorStatusOK(p, CollectorDockerNetworks) {
		plan.networks = dockerNetworks(d.Networks, collectorTruncated(p, CollectorDockerNetworks))
	}
	if collectorStatusOK(p, CollectorSwarmServices) {
		sw := plan.engine
		switch {
		case sw == nil || sw.Swarm == nil || sw.Swarm.State != "active" || sw.Swarm.Role != "manager":
			plan.notes = append(plan.notes, "swarm_services ignored: the push isn't from an active Swarm manager")
		case sw.Swarm.ClusterID == "":
			plan.notes = append(plan.notes, "swarm_services ignored: no cluster_id")
		default:
			plan.swarm = &store.SwarmServicesInput{
				ClusterID: sw.Swarm.ClusterID,
				Set:       swarmServicesSet(d.SwarmServices, collectorTruncated(p, CollectorSwarmServices)),
			}
		}
	}
	return plan
}

// dockerID accepts an engine object id / digest: printable, no spaces, at
// most 128 bytes ("sha256:" + 64 hex fits).
func dockerID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 128 {
		return ""
	}
	for _, r := range s {
		if r <= ' ' || r > '~' {
			return ""
		}
	}
	return s
}

func rfc3339(s string) any {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
	if err != nil {
		return nil
	}
	return t.UTC()
}

// labelText reads one label for a derived column. labels must already be
// filtered (dockerLabels), so the column can only hold an allowlisted key.
func labelText(labels map[string]string, key string) any {
	return nullText(labels[key], 256)
}

func validProto(p string) bool { return p == "tcp" || p == "udp" || p == "sctp" }

// containerPort is one host_containers.ports element.
type containerPort struct {
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      int    `json:"host_port,omitempty"`
	ContainerPort int    `json:"container_port"`
	Proto         string `json:"proto"`
}

// containerMount is one host_containers.mounts element.
type containerMount struct {
	Type        string `json:"type"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination"`
	RW          bool   `json:"rw"`
}

func containersSet(in []DockerContainer, additive bool) hostfacts.Set {
	var rows []hostfacts.Row
	for _, c := range in {
		id := dockerID(c.ID)
		if id == "" {
			continue
		}
		if len(rows) == maxDockerContainers {
			additive = true
			break
		}
		labels := dockerLabels(c.Labels)
		startedAt := rfc3339(c.StartedAt)
		inspectErr := hostfacts.Clip(c.InspectError, maxDockerInspectErrorSize)
		r := hostfacts.Row{
			Key: id,
			Values: []any{id, hostfacts.Clip(c.Name, 256), nullText(c.Image, 512), nullText(c.ImageID, 128), nullText(c.State, 32),
				labelText(labels, "com.docker.compose.project"), labelText(labels, "com.docker.compose.service"),
				labelText(labels, "com.docker.stack.namespace"), labelText(labels, "com.docker.swarm.service.id"),
				labelText(labels, "com.docker.swarm.service.name"), labelText(labels, "com.docker.swarm.task.id"),
				labels},
			Live: []any{startedAt, nullText(inspectErr, maxDockerInspectErrorSize)},
		}
		if inspectErr != "" {
			// Partial: every inspect field is unknown, whatever was sent.
			r.Partial = true
			r.Live[0] = nil
		} else {
			var cut bool
			var ports []containerPort
			ports, cut = containerPorts(c.Ports)
			additive = additive || cut
			var mounts []containerMount
			mounts, cut = containerMounts(c.Mounts)
			additive = additive || cut
			var nets []string
			nets, cut = textList(c.Networks, 256, maxDockerNetworksPerItem, true)
			additive = additive || cut
			var privileged any
			if c.Privileged != nil {
				privileged = *c.Privileged
			}
			r.Detail = []any{ports, nets, nullText(c.NetworkMode, 256), privileged, nullText(c.RestartPolicy, 32), mounts}
		}
		rows = append(rows, r)
	}
	return hostfacts.NewSet(KindDockerContainers, hostfacts.ContainersTable, "", rows, additive)
}

// containerPorts validates, sorts and dedupes a container's port list.
// An exposed-only port has no host side. cut reports hitting the cap.
func containerPorts(in []DockerPort) (out []containerPort, cut bool) {
	out = []containerPort{}
	for _, p := range in {
		if p.ContainerPort < 1 || p.ContainerPort > 65535 || !validProto(p.Proto) || p.HostPort < 0 || p.HostPort > 65535 {
			continue
		}
		cp := containerPort{ContainerPort: p.ContainerPort, Proto: p.Proto, HostPort: p.HostPort}
		if ip := strings.TrimSpace(p.HostIP); ip != "" {
			a, err := netip.ParseAddr(ip)
			if err != nil || a.Zone() != "" {
				continue
			}
			cp.HostIP = a.String()
		}
		out = append(out, cp)
	}
	slices.SortFunc(out, func(a, b containerPort) int {
		return cmp.Or(cmp.Compare(a.ContainerPort, b.ContainerPort), cmp.Compare(a.Proto, b.Proto),
			cmp.Compare(a.HostIP, b.HostIP), cmp.Compare(a.HostPort, b.HostPort))
	})
	out = slices.Compact(out)
	if len(out) > maxDockerPortsPerItem {
		out, cut = out[:maxDockerPortsPerItem], true
	}
	return out, cut
}

// containerMounts clips and sorts mounts by destination. A source is kept
// only for bind mounts, whatever the agent sent (PROTOCOL.md "Never sent").
func containerMounts(in []DockerMount) (out []containerMount, cut bool) {
	out = []containerMount{}
	for _, m := range in {
		cm := containerMount{Type: hostfacts.Clip(m.Type, 32), Destination: hostfacts.Clip(m.Destination, 4096), RW: m.RW}
		if cm.Type == "" || cm.Destination == "" {
			continue
		}
		if cm.Type == "bind" {
			cm.Source = hostfacts.Clip(m.Source, 4096)
		}
		out = append(out, cm)
	}
	slices.SortFunc(out, func(a, b containerMount) int {
		return cmp.Or(cmp.Compare(a.Destination, b.Destination), cmp.Compare(a.Type, b.Type), cmp.Compare(a.Source, b.Source))
	})
	out = slices.Compact(out)
	if len(out) > maxDockerMountsPerItem {
		out, cut = out[:maxDockerMountsPerItem], true
	}
	return out, cut
}

// textList clips each entry to n bytes, drops empty ones, optionally sorts
// and dedupes, and cuts to max. Never nil.
func textList(in []string, n, max int, sorted bool) (out []string, cut bool) {
	out = []string{}
	for _, s := range in {
		if s = hostfacts.Clip(s, n); s != "" {
			out = append(out, s)
		}
	}
	if sorted {
		slices.Sort(out)
		out = slices.Compact(out)
	}
	if len(out) > max {
		out, cut = out[:max], true
	}
	return out, cut
}

// imagesSet builds the host_images set and the content to intern for every
// fully inspected image. The platform strings are used as-is ("" when the
// engine reports none) in both, so host_images joins container_images.
func imagesSet(in []DockerImage, additive bool) (hostfacts.Set, []store.ContainerImage) {
	var (
		rows    []hostfacts.Row
		content []store.ContainerImage
	)
	for _, im := range in {
		id := dockerID(im.ID)
		if id == "" {
			continue
		}
		if len(rows) == maxDockerImages {
			additive = true
			break
		}
		tags, cutT := textList(im.RepoTags, 512, maxDockerRefsPerImage, true)
		digests, cutD := textList(im.RepoDigests, 512, maxDockerRefsPerImage, true)
		additive = additive || cutT || cutD
		inspectErr := hostfacts.Clip(im.InspectError, maxDockerInspectErrorSize)
		r := hostfacts.Row{
			Key:    id,
			Values: []any{id, tags, digests},
			Live:   []any{nullText(inspectErr, maxDockerInspectErrorSize)},
		}
		if inspectErr != "" {
			r.Partial = true
		} else {
			os, arch, variant := hostfacts.Clip(im.OS, 32), hostfacts.Clip(im.Arch, 32), hostfacts.Clip(im.Variant, 32)
			r.Detail = []any{os, arch, variant}
			layers, cutL := textList(im.Layers, 128, maxDockerLayersPerImage, false) // chain order, base first
			additive = additive || cutL
			ci := store.ContainerImage{ImageID: id, OS: os, Arch: arch, Variant: variant, Layers: layers, Labels: dockerLabels(im.Labels)}
			if t, ok := rfc3339(im.Created).(time.Time); ok {
				ci.Created = &t
			}
			content = append(content, ci)
		}
		rows = append(rows, r)
	}
	return hostfacts.NewSet(KindDockerImages, hostfacts.HostImagesTable, "", rows, additive), content
}

func dockerEngine(e *DockerEngine, s *DockerSwarm) *store.DockerEngineInput {
	out := &store.DockerEngineInput{
		Version:       hostfacts.Clip(e.Version, 64),
		APIVersion:    hostfacts.Clip(e.APIVersion, 16),
		StorageDriver: hostfacts.Clip(e.StorageDriver, 64),
		Rootless:      e.Rootless,
	}
	if e.ImageStore == "containerd" || e.ImageStore == "graphdriver" {
		out.ImageStore = e.ImageStore
	}
	if s != nil && (s.State == "active" || s.State == "locked") {
		sw := &store.DockerSwarmInput{State: s.State, NodeID: dockerID(s.NodeID), ClusterID: dockerID(s.ClusterID)}
		if s.Role == "manager" || s.Role == "worker" {
			sw.Role = s.Role
		}
		out.Swarm = sw
	}
	return out
}

// dockerNetwork is one host_docker.networks element.
type dockerNetwork struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Driver   string   `json:"driver"`
	Scope    string   `json:"scope"`
	Internal bool     `json:"internal"`
	Subnets  []string `json:"subnets"`
}

func dockerNetworks(in []DockerNetwork, truncated bool) *store.DockerNetworksInput {
	out := []dockerNetwork{}
	for _, n := range in {
		id := dockerID(n.ID)
		if id == "" {
			continue
		}
		if len(out) == maxDockerNetworks {
			truncated = true
			break
		}
		subnets, cut := textList(n.Subnets, 64, maxDockerSubnetsPerNet, true)
		truncated = truncated || cut
		out = append(out, dockerNetwork{ID: id, Name: hostfacts.Clip(n.Name, 256), Driver: hostfacts.Clip(n.Driver, 64),
			Scope: hostfacts.Clip(n.Scope, 16), Internal: n.Internal, Subnets: subnets})
	}
	slices.SortFunc(out, func(a, b dockerNetwork) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID)) })
	return &store.DockerNetworksInput{Networks: out, Truncated: truncated}
}

// swarmPort is one swarm_services.ports element.
type swarmPort struct {
	Published   int    `json:"published,omitempty"`
	Target      int    `json:"target"`
	Proto       string `json:"proto"`
	PublishMode string `json:"publish_mode"`
}

func nonNegative(p *int) any {
	if p == nil || *p < 0 {
		return nil
	}
	return *p
}

func swarmServicesSet(in []SwarmService, additive bool) hostfacts.Set {
	var rows []hostfacts.Row
	for _, s := range in {
		id := dockerID(s.ID)
		name := hostfacts.Clip(s.Name, 256)
		if id == "" || name == "" {
			continue
		}
		if len(rows) == maxSwarmServices {
			additive = true
			break
		}
		ports := []swarmPort{}
		for _, p := range s.Ports {
			if p.Target < 1 || p.Target > 65535 || p.Published < 0 || p.Published > 65535 || !validProto(p.Proto) {
				continue
			}
			ports = append(ports, swarmPort{Published: p.Published, Target: p.Target, Proto: p.Proto, PublishMode: hostfacts.Clip(p.PublishMode, 16)})
		}
		slices.SortFunc(ports, func(a, b swarmPort) int {
			return cmp.Or(cmp.Compare(a.Target, b.Target), cmp.Compare(a.Proto, b.Proto),
				cmp.Compare(a.Published, b.Published), cmp.Compare(a.PublishMode, b.PublishMode))
		})
		ports = slices.Compact(ports)
		if len(ports) > maxDockerPortsPerItem {
			ports, additive = ports[:maxDockerPortsPerItem], true
		}
		labels := dockerLabels(s.Labels)
		rows = append(rows, hostfacts.Row{
			Key: id,
			Values: []any{id, name, nullText(s.Image, 512), nullText(s.Mode, 32), nonNegative(s.Replicas),
				labelText(labels, "com.docker.stack.namespace"), labels, ports},
			Live: []any{nonNegative(s.RunningTasks), nonNegative(s.DesiredTasks)},
		})
	}
	return hostfacts.NewSet(KindSwarmServices, hostfacts.SwarmServicesTable, "", rows, additive)
}
