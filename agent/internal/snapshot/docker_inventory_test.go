package snapshot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/swarm"

	"github.com/pippinmole/upkeep.sh/agent/internal/collector"
	"github.com/pippinmole/upkeep.sh/agent/internal/dockerapi/dockerapitest"
)

// inventoryFake is an engine with one container, one image and one
// network.
func inventoryFake() *dockerapitest.Fake {
	f := engineFake(swarm.Info{})
	f.Containers = []container.Summary{{ID: "c1"}}
	f.ContainerInspects = map[string]container.InspectResponse{"c1": {
		ID: "c1", Name: "/web", Image: "sha256:i1",
		State:      &container.State{Status: container.StateRunning, StartedAt: "2026-09-27T10:00:00Z"},
		HostConfig: &container.HostConfig{NetworkMode: "bridge", RestartPolicy: container.RestartPolicy{Name: "always"}},
		Config:     &container.Config{Image: "nginx:1", Env: []string{"TOKEN=hunter2"}},
		NetworkSettings: &container.NetworkSettings{
			Ports:    network.PortMap{network.MustParsePort("80/tcp"): {{HostIP: netip.MustParseAddr("0.0.0.0"), HostPort: "8080"}}},
			Networks: map[string]*network.EndpointSettings{"bridge": {}},
		},
		Mounts: []container.MountPoint{{Type: mount.TypeVolume, Name: "secretvol", Source: "/var/lib/docker/volumes/secretvol/_data", Destination: "/data", RW: true}},
	}}
	f.Images = []image.Summary{{ID: "sha256:i1"}}
	f.ImageInspects = map[string]image.InspectResponse{"sha256:i1": {ID: "sha256:i1", RepoTags: []string{"nginx:1"},
		Created: "2026-09-01T00:00:00Z", Os: "linux", Architecture: "amd64", RootFS: image.RootFS{Layers: []string{"sha256:l1"}}}}
	f.Networks = []network.Summary{{Network: network.Network{ID: "n1", Name: "bridge", Driver: "bridge", Scope: "local",
		IPAM: network.IPAM{Config: []network.IPAMConfig{{Subnet: netip.MustParsePrefix("172.17.0.0/16")}}}}}}
	return f
}

// docker_containers, docker_images and docker_networks each own their own
// section and status.
func TestDockerInventory(t *testing.T) {
	fake := inventoryFake()
	c, _ := dockerCollector(fake, nil)
	snap := c.Collect(context.Background(), ubuntu())
	for _, name := range []string{collector.CollectorDockerContainers, collector.CollectorDockerImages, collector.CollectorDockerNetworks} {
		if st := snap.Collectors[name]; st != collector.OK() {
			t.Errorf("%s = %+v, want ok", name, st)
		}
	}
	b, _ := json.Marshal(snap.Docker)
	for _, want := range []string{
		`"containers":[{"id":"c1","name":"web","image":"nginx:1","image_id":"sha256:i1","state":"running","started_at":"2026-09-27T10:00:00Z","ports":[{"host_ip":"0.0.0.0","host_port":8080,"container_port":80,"proto":"tcp"}],"networks":["bridge"],"network_mode":"bridge","privileged":false,"restart_policy":"always","mounts":[{"type":"volume","destination":"/data","rw":true}]}]`,
		`"images":[{"id":"sha256:i1","repo_tags":["nginx:1"],"created":"2026-09-01T00:00:00Z","os":"linux","arch":"amd64","layers":["sha256:l1"]}]`,
		`"networks":[{"id":"n1","name":"bridge","driver":"bridge","scope":"local","internal":false,"subnets":["172.17.0.0/16"]}]`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("docker block missing %s\n%s", want, b)
		}
	}
	if strings.Contains(string(b), "hunter2") || strings.Contains(string(b), "secretvol") {
		t.Errorf("docker block leaks: %s", b)
	}
}

// One collector failing leaves the others' sections and statuses alone,
// and its own section out.
func TestDockerInventoryErrors(t *testing.T) {
	fake := inventoryFake()
	fake.ContainerInspectErr = errors.New("inspect boom")
	fake.NetworksErr = errors.New("network boom")
	many := make([]image.Summary, collector.MaxDockerImages+1)
	for i := range many {
		many[i].ID = fmt.Sprintf("sha256:%064x", i)
		fake.ImageInspects[many[i].ID] = image.InspectResponse{ID: many[i].ID}
	}
	fake.Images = many
	c, _ := dockerCollector(fake, nil)
	snap := c.Collect(context.Background(), ubuntu())

	if st := snap.Collectors[collector.CollectorDockerContainers]; st.Status != collector.StatusError || !strings.Contains(st.Error, "inspect boom") {
		t.Errorf("docker_containers = %+v, want error", st)
	}
	if st := snap.Collectors[collector.CollectorDockerNetworks]; st.Status != collector.StatusError || !strings.Contains(st.Error, "network boom") {
		t.Errorf("docker_networks = %+v, want error", st)
	}
	if st := snap.Collectors[collector.CollectorDockerImages]; st != collector.OKTruncated(true) {
		t.Errorf("docker_images = %+v, want ok truncated", st)
	}
	if snap.Docker == nil || snap.Docker.Containers != nil || snap.Docker.Networks != nil || len(snap.Docker.Images) != collector.MaxDockerImages {
		t.Errorf("docker = %+v", snap.Docker)
	}
	if st := snap.Collectors[collector.CollectorDockerEngine]; st != collector.OK() {
		t.Errorf("docker_engine = %+v, want ok", st)
	}
}
