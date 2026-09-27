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
		// wantServices is swarm_services' status; nil means absent (the
		// manager-side collector isn't built yet).
		wantServices *collector.CollectorStatus
	}{
		{"not in swarm", swarm.Info{LocalNodeState: swarm.LocalNodeStateInactive}, nil, ptr(collector.Skipped("not in a swarm"))},
		{"worker", worker, &collector.DockerSwarm{NodeID: "n2", Role: "worker"}, ptr(collector.Skipped("not a swarm manager"))},
		{"manager", manager, &collector.DockerSwarm{NodeID: "n1", ClusterID: "c1", Role: "manager"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := engineFake(tt.swarm)
			c, _ := dockerCollector(fake, nil)
			snap := c.Collect(context.Background(), ubuntu())

			want := map[string]collector.CollectorStatus{collector.CollectorDockerEngine: collector.OK()}
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
	if snap.Docker != nil {
		t.Errorf("docker = %+v, want nil", snap.Docker)
	}
	if !fake.Closed {
		t.Error("docker client not closed")
	}
}

func ptr[T any](v T) *T { return &v }
