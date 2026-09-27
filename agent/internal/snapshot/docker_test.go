package snapshot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/moby/moby/api/types/swarm"
	"github.com/moby/moby/api/types/system"
	"github.com/moby/moby/client"

	"github.com/pippinmole/upkeep.sh/agent/internal/collector"
	"github.com/pippinmole/upkeep.sh/agent/internal/dockerapi"
	"github.com/pippinmole/upkeep.sh/agent/internal/dockerapi/dockerapitest"
	"github.com/pippinmole/upkeep.sh/agent/internal/target"
)

// dockerCollector is testCollector with a stub Docker opener that returns
// fake (or err) and records the sockets it was asked to open.
func dockerCollector(fake *dockerapitest.Fake, err error) (*Collector, *[]string) {
	var opened []string
	c := testCollector()
	c.DockerSocket = "/var/run/docker.sock"
	c.OpenDocker = func(_ context.Context, socket string) (dockerapi.Client, error) {
		opened = append(opened, socket)
		if err != nil {
			return nil, err
		}
		return fake, nil
	}
	return c, &opened
}

func engineFake(sw swarm.Info) *dockerapitest.Fake {
	return &dockerapitest.Fake{
		VersionResult: client.ServerVersionResult{
			Version: "29.8.0", APIVersion: "1.56",
			Components: []system.ComponentVersion{{Name: "Engine", Version: "29.8.0"}},
		},
		InfoResult: system.Info{
			Driver:       "overlayfs",
			DriverStatus: [][2]string{{"driver-type", "io.containerd.snapshotter.v1"}},
			Swarm:        sw,
		},
	}
}

func dockerStatuses(snap collector.Snapshot) map[string]collector.CollectorStatus {
	out := map[string]collector.CollectorStatus{}
	for _, name := range dockerCollectors {
		if st, ok := snap.Collectors[name]; ok {
			out[name] = st
		}
	}
	return out
}

func allDocker(st collector.CollectorStatus) map[string]collector.CollectorStatus {
	out := map[string]collector.CollectorStatus{}
	for _, name := range dockerCollectors {
		out[name] = st
	}
	return out
}

// sshTarget is a remote-mode target over a fixture directory.
type sshTarget struct{ fsys fs.FS }

func (s sshTarget) Ref() string       { return "r1" }
func (s sshTarget) Mode() target.Mode { return target.ModeSSH }
func (s sshTarget) FS() fs.FS         { return s.fsys }

func ubuntu() target.Target { return target.NewLocal("testdata/ubuntu", "testdata/proc") }

// Remote targets never open the socket, and report "remote host" (which
// the dashboard keys on) for every Docker collector.
func TestDockerRemoteHost(t *testing.T) {
	c, opened := dockerCollector(engineFake(swarm.Info{}), nil)
	snap := c.Collect(context.Background(), sshTarget{os.DirFS("testdata/ubuntu")})
	if len(*opened) != 0 {
		t.Errorf("remote target opened the docker socket: %v", *opened)
	}
	if got, want := dockerStatuses(snap), allDocker(collector.Skipped("remote host")); !reflect.DeepEqual(got, want) {
		t.Errorf("statuses = %+v, want %+v", got, want)
	}
	if snap.Docker != nil {
		t.Errorf("docker = %+v, want nil", snap.Docker)
	}
}

func TestDockerNotLinux(t *testing.T) {
	c, opened := dockerCollector(engineFake(swarm.Info{}), nil)
	snap := c.Collect(context.Background(), fsTarget{fstest.MapFS{"Windows/System32/kernel32.dll": {}}})
	if len(*opened) != 0 {
		t.Errorf("non-Linux target opened the docker socket: %v", *opened)
	}
	for name, st := range dockerStatuses(snap) {
		if st.Status != collector.StatusSkipped || !strings.Contains(st.Reason, "windows") {
			t.Errorf("%s = %+v, want skipped (not implemented for windows)", name, st)
		}
	}
	if len(dockerStatuses(snap)) != len(dockerCollectors) {
		t.Errorf("statuses = %+v, want all Docker collectors", dockerStatuses(snap))
	}
}

func TestDockerSocketNotMounted(t *testing.T) {
	notMounted := fmt.Errorf("%w: nothing at /var/run/docker.sock", dockerapi.ErrSocketNotMounted)
	c, opened := dockerCollector(nil, notMounted)
	snap := c.Collect(context.Background(), ubuntu())
	if !reflect.DeepEqual(*opened, []string{"/var/run/docker.sock"}) {
		t.Errorf("opened = %v", *opened)
	}
	if got, want := dockerStatuses(snap), allDocker(collector.Skipped("docker socket not mounted")); !reflect.DeepEqual(got, want) {
		t.Errorf("statuses = %+v, want %+v", got, want)
	}
	if snap.Docker != nil {
		t.Errorf("docker = %+v, want nil", snap.Docker)
	}

	// No socket configured is the same state.
	c.DockerSocket = ""
	snap = c.Collect(context.Background(), ubuntu())
	if got, want := dockerStatuses(snap), allDocker(collector.Skipped("docker socket not mounted")); !reflect.DeepEqual(got, want) {
		t.Errorf("no socket: statuses = %+v, want %+v", got, want)
	}
}

// The production opener reports a missing socket as ErrSocketNotMounted
// and never hands back a typed-nil client.
func TestOpenDockerNotMounted(t *testing.T) {
	cl, err := openDocker(context.Background(), filepath.Join(t.TempDir(), "docker.sock"))
	if !errors.Is(err, dockerapi.ErrSocketNotMounted) || cl != nil {
		t.Errorf("openDocker = %v, %v; want nil client, ErrSocketNotMounted", cl, err)
	}
}

func TestDockerEngineUnavailable(t *testing.T) {
	c, _ := dockerCollector(nil, errors.New("docker engine at /var/run/docker.sock: connection refused"))
	snap := c.Collect(context.Background(), ubuntu())
	want := allDocker(collector.Skipped("docker engine unavailable"))
	want[collector.CollectorDockerEngine] = collector.Failed(errors.New("docker engine at /var/run/docker.sock: connection refused"))
	if got := dockerStatuses(snap); !reflect.DeepEqual(got, want) {
		t.Errorf("statuses = %+v, want %+v", got, want)
	}
	if snap.Docker != nil {
		t.Errorf("docker = %+v, want nil", snap.Docker)
	}
}

func TestDockerEngineOK(t *testing.T) {
	manager := swarm.Info{NodeID: "n1", LocalNodeState: swarm.LocalNodeStateActive, ControlAvailable: true,
		Cluster: &swarm.ClusterInfo{ID: "c1"}}
	worker := swarm.Info{NodeID: "n2", LocalNodeState: swarm.LocalNodeStateActive}
	tests := []struct {
		name      string
		swarm     swarm.Info
		wantSwarm *collector.DockerSwarm
		// wantServices is swarm_services' status; nil means absent.
		wantServices *collector.CollectorStatus
	}{
		{"not in swarm", swarm.Info{LocalNodeState: swarm.LocalNodeStateInactive}, nil, ptr(collector.Skipped("not in a swarm"))},
		{"worker", worker, &collector.DockerSwarm{State: "active", NodeID: "n2", Role: "worker"}, ptr(collector.Skipped("not a swarm manager"))},
		// Locked (autolock): in a Swarm, but no role and no service list
		// until unlocked.
		{"locked", swarm.Info{LocalNodeState: swarm.LocalNodeStateLocked}, &collector.DockerSwarm{State: "locked"}, ptr(collector.Skipped("swarm locked"))},
		// A manager with no services: ok, and no swarm_services section.
		{"manager", manager, &collector.DockerSwarm{State: "active", NodeID: "n1", ClusterID: "c1", Role: "manager"}, ptr(collector.OK())},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := engineFake(tt.swarm)
			c, _ := dockerCollector(fake, nil)
			snap := c.Collect(context.Background(), ubuntu())

			// An engine with no containers, images or networks: those
			// collectors are ok with nothing to report.
			want := map[string]collector.CollectorStatus{
				collector.CollectorDockerEngine:     collector.OK(),
				collector.CollectorDockerContainers: collector.OK(),
				collector.CollectorDockerImages:     collector.OK(),
				collector.CollectorDockerNetworks:   collector.OK(),
			}
			if tt.wantServices != nil {
				want[collector.CollectorSwarmServices] = *tt.wantServices
			}
			if got := dockerStatuses(snap); !reflect.DeepEqual(got, want) {
				t.Errorf("statuses = %+v, want %+v", got, want)
			}
			wantEngine := &collector.DockerEngine{Version: "29.8.0", APIVersion: "1.56", StorageDriver: "overlayfs", ImageStore: "containerd"}
			if snap.Docker == nil || !reflect.DeepEqual(snap.Docker.Engine, wantEngine) || !reflect.DeepEqual(snap.Docker.Swarm, tt.wantSwarm) {
				t.Fatalf("docker = %+v", snap.Docker)
			}
			if !fake.Closed {
				t.Error("docker client not closed")
			}
			b, _ := json.Marshal(snap)
			if !strings.Contains(string(b), `"docker":{"engine":{"version":"29.8.0","api_version":"1.56","storage_driver":"overlayfs","image_store":"containerd","rootless":false}`) {
				t.Errorf("payload docker block: %s", b)
			}
		})
	}
}

// The engine answered Open but /info failed: docker_engine is an error,
// swarm_services can't know the role, and the client is still closed.
func TestDockerEngineCollectFails(t *testing.T) {
	fake := engineFake(swarm.Info{})
	fake.InfoErr = errors.New("boom")
	c, _ := dockerCollector(fake, nil)
	snap := c.Collect(context.Background(), ubuntu())
	st := snap.Collectors[collector.CollectorDockerEngine]
	if st.Status != collector.StatusError || !strings.Contains(st.Error, "boom") {
		t.Errorf("docker_engine = %+v, want error", st)
	}
	if st := snap.Collectors[collector.CollectorSwarmServices]; st != collector.Skipped("docker engine unavailable") {
		t.Errorf("swarm_services = %+v", st)
	}
	// The inventory collectors don't need /version or /info: they still
	// run (here with nothing to report).
	for _, name := range []string{collector.CollectorDockerContainers, collector.CollectorDockerImages, collector.CollectorDockerNetworks} {
		if st := snap.Collectors[name]; st != collector.OK() {
			t.Errorf("%s = %+v, want ok", name, st)
		}
	}
	if snap.Docker != nil {
		t.Errorf("docker = %+v, want nil", snap.Docker)
	}
	if !fake.Closed {
		t.Error("docker client not closed")
	}
}

// On a manager, swarm_services lists the services; a demotion (or leaving
// the Swarm) between /info and the list is a skip with the node's actual
// state, anything else an error.
func TestDockerSwarmServices(t *testing.T) {
	manager := swarm.Info{NodeID: "n1", LocalNodeState: swarm.LocalNodeStateActive, ControlAvailable: true,
		Cluster: &swarm.ClusterInfo{ID: "c1"}}
	three := uint64(3)
	svc := swarm.Service{
		ID: "s1",
		Spec: swarm.ServiceSpec{
			Annotations: swarm.Annotations{Name: "web_api", Labels: map[string]string{
				"com.docker.stack.namespace": "web", "traefik.http.middlewares.a.basicauth.users": "admin:hash",
			}},
			TaskTemplate: swarm.TaskSpec{ContainerSpec: &swarm.ContainerSpec{Image: "api:1", Env: []string{"TOKEN=hunter2"}}},
			Mode:         swarm.ServiceMode{Replicated: &swarm.ReplicatedService{Replicas: &three}},
		},
		Endpoint: swarm.Endpoint{Ports: []swarm.PortConfig{
			{Protocol: "tcp", TargetPort: 8443, PublishedPort: 443, PublishMode: swarm.PortConfigPublishModeIngress},
		}},
		ServiceStatus: &swarm.ServiceStatus{RunningTasks: 2, DesiredTasks: 3},
	}
	many := make([]swarm.Service, collector.MaxSwarmServices+1)
	for i := range many {
		many[i].ID = fmt.Sprintf("s%05d", i)
	}
	tests := []struct {
		name     string
		services []swarm.Service
		err      error
		want     collector.CollectorStatus
		wantLen  int
	}{
		{"services", []swarm.Service{svc}, nil, collector.OK(), 1},
		{"truncated", many, nil, collector.OKTruncated(true), collector.MaxSwarmServices},
		{"demoted", nil, errors.New("Error response from daemon: This node is not a swarm manager. Worker nodes can't be used to view or modify cluster state."), collector.Skipped("not a swarm manager"), 0},
		{"left swarm", nil, errors.New("Error response from daemon: This node is not part of a swarm"), collector.Skipped("not in a swarm"), 0},
		{"locked since info", nil, errors.New("Error response from daemon: Swarm is encrypted and needs to be unlocked before it can be used."), collector.Skipped("swarm locked"), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := engineFake(manager)
			fake.Services, fake.ServicesErr = tt.services, tt.err
			c, _ := dockerCollector(fake, nil)
			snap := c.Collect(context.Background(), ubuntu())
			if st := snap.Collectors[collector.CollectorSwarmServices]; st != tt.want {
				t.Errorf("swarm_services = %+v, want %+v", st, tt.want)
			}
			if snap.Docker == nil || len(snap.Docker.SwarmServices) != tt.wantLen {
				t.Fatalf("docker = %+v, want %d services", snap.Docker, tt.wantLen)
			}
		})
	}

	fake := engineFake(manager)
	fake.Services = []swarm.Service{svc}
	c, _ := dockerCollector(fake, nil)
	b, _ := json.Marshal(c.Collect(context.Background(), ubuntu()))
	if !strings.Contains(string(b), `"swarm_services":[{"id":"s1","name":"web_api","image":"api:1","mode":"replicated","replicas":3,"running_tasks":2,"desired_tasks":3,"labels":{"com.docker.stack.namespace":"web"},"ports":[{"published":443,"target":8443,"proto":"tcp","publish_mode":"ingress"}]}]`) {
		t.Errorf("payload swarm_services: %s", b)
	}
	if strings.Contains(string(b), "hunter2") || strings.Contains(string(b), "traefik") {
		t.Errorf("payload leaks the service spec: %s", b)
	}

	// Any other failure (here a manager without quorum) is an error.
	fake = engineFake(manager)
	fake.ServicesErr = errors.New("rpc error: code = Unknown desc = The swarm does not have a leader.")
	c, _ = dockerCollector(fake, nil)
	snap := c.Collect(context.Background(), ubuntu())
	if st := snap.Collectors[collector.CollectorSwarmServices]; st.Status != collector.StatusError || !strings.Contains(st.Error, "does not have a leader") {
		t.Errorf("swarm_services = %+v, want error", st)
	}
	if snap.Docker == nil || snap.Docker.SwarmServices != nil {
		t.Errorf("docker = %+v, want no swarm_services", snap.Docker)
	}
}

func ptr[T any](v T) *T { return &v }
