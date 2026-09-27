package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/swarm"

	"github.com/pippinmole/upkeep.sh/agent/internal/dockerapi/dockerapitest"
)

func u64(n uint64) *uint64 { return &n }
func intp(n int) *int      { return &n }

func TestCollectSwarmServices(t *testing.T) {
	web := swarm.Service{
		ID: "svc-b",
		Spec: swarm.ServiceSpec{
			Annotations: swarm.Annotations{
				Name: "web_api",
				Labels: map[string]string{
					"com.docker.stack.namespace":              "web",
					"com.docker.stack.image":                  "ghcr.io/me/api:1",
					"traefik.http.middlewares.auth.basicauth": "admin:$apr1$secret",
					"com.docker.compose.mytoken":              "hunter2",
				},
			},
			TaskTemplate: swarm.TaskSpec{ContainerSpec: &swarm.ContainerSpec{
				Image:   "ghcr.io/me/api:1@sha256:abc",
				Env:     []string{"DB_PASSWORD=hunter2"},
				Args:    []string{"--token", "hunter2"},
				Command: []string{"/bin/api"},
				Labels:  map[string]string{"org.opencontainers.image.version": "container-label"},
				Secrets: []*swarm.SecretReference{{SecretName: "db_password", SecretID: "sec1"}},
				Configs: []*swarm.ConfigReference{{ConfigName: "cfg", ConfigID: "cfg1"}},
				Mounts: []mount.Mount{{Type: mount.TypeVolume, Source: "creds", Target: "/data",
					VolumeOptions: &mount.VolumeOptions{DriverConfig: &mount.Driver{Options: map[string]string{"password": "hunter2"}}}}},
			}},
			Mode: swarm.ServiceMode{Replicated: &swarm.ReplicatedService{Replicas: u64(2)}},
			EndpointSpec: &swarm.EndpointSpec{Ports: []swarm.PortConfig{
				{TargetPort: 8443, PublishedPort: 443},
				{TargetPort: 9000},
			}},
		},
		// The allocator's view wins over the spec: 9000 got a port.
		Endpoint: swarm.Endpoint{Ports: []swarm.PortConfig{
			{Protocol: "udp", TargetPort: 8443, PublishedPort: 443, PublishMode: swarm.PortConfigPublishModeIngress},
			{Protocol: "tcp", TargetPort: 9000, PublishedPort: 30001, PublishMode: swarm.PortConfigPublishModeIngress},
			{Protocol: "tcp", TargetPort: 8443, PublishedPort: 443, PublishMode: swarm.PortConfigPublishModeIngress},
		}},
		ServiceStatus: &swarm.ServiceStatus{RunningTasks: 1, DesiredTasks: 2},
	}
	agent := swarm.Service{
		ID: "svc-a",
		Spec: swarm.ServiceSpec{
			Annotations:  swarm.Annotations{Name: "monitoring_agent"},
			TaskTemplate: swarm.TaskSpec{ContainerSpec: &swarm.ContainerSpec{Image: "agent:2"}},
			Mode:         swarm.ServiceMode{Global: &swarm.GlobalService{}},
			// Not allocated yet: fall back to the spec, with swarmkit's
			// defaults for the empty protocol and publish mode.
			EndpointSpec: &swarm.EndpointSpec{Ports: []swarm.PortConfig{
				{TargetPort: 9100, PublishedPort: 9100, PublishMode: swarm.PortConfigPublishModeHost},
				{TargetPort: 80},
			}},
		},
	}
	job := swarm.Service{
		ID: "svc-c",
		Spec: swarm.ServiceSpec{
			Annotations:  swarm.Annotations{Name: "migrate"},
			TaskTemplate: swarm.TaskSpec{ContainerSpec: &swarm.ContainerSpec{Image: "migrate:1"}},
			Mode:         swarm.ServiceMode{ReplicatedJob: &swarm.ReplicatedJob{MaxConcurrent: u64(2), TotalCompletions: u64(5)}},
		},
	}
	gjob := swarm.Service{
		ID: "svc-d",
		Spec: swarm.ServiceSpec{
			Annotations:  swarm.Annotations{Name: "prune"},
			TaskTemplate: swarm.TaskSpec{ContainerSpec: &swarm.ContainerSpec{Image: "docker:cli"}},
			Mode:         swarm.ServiceMode{GlobalJob: &swarm.GlobalJob{}},
		},
		// Counts of 0 are sent, not omitted.
		ServiceStatus: &swarm.ServiceStatus{CompletedTasks: 3},
	}
	scaledToZero := swarm.Service{
		ID: "svc-e",
		Spec: swarm.ServiceSpec{
			Annotations: swarm.Annotations{Name: "idle"},
			// Plugin service: no container spec, no image.
			TaskTemplate: swarm.TaskSpec{Runtime: swarm.RuntimePlugin},
			Mode:         swarm.ServiceMode{Replicated: &swarm.ReplicatedService{Replicas: u64(0)}},
		},
	}

	f := &dockerapitest.Fake{Services: []swarm.Service{web, scaledToZero, gjob, agent, job}}
	got, truncated, err := CollectSwarmServices(context.Background(), f)
	if err != nil || truncated {
		t.Fatalf("err=%v truncated=%v", err, truncated)
	}
	want := []SwarmService{
		{ID: "svc-a", Name: "monitoring_agent", Image: "agent:2", Mode: "global",
			Ports: []SwarmPort{
				{Target: 80, Proto: "tcp", PublishMode: "ingress"},
				{Published: 9100, Target: 9100, Proto: "tcp", PublishMode: "host"},
			}},
		{ID: "svc-b", Name: "web_api", Image: "ghcr.io/me/api:1@sha256:abc", Mode: "replicated", Replicas: intp(2),
			RunningTasks: intp(1), DesiredTasks: intp(2),
			Labels: map[string]string{"com.docker.stack.namespace": "web", "com.docker.stack.image": "ghcr.io/me/api:1"},
			Ports: []SwarmPort{
				{Published: 443, Target: 8443, Proto: "tcp", PublishMode: "ingress"},
				{Published: 443, Target: 8443, Proto: "udp", PublishMode: "ingress"},
				{Published: 30001, Target: 9000, Proto: "tcp", PublishMode: "ingress"},
			}},
		{ID: "svc-c", Name: "migrate", Image: "migrate:1", Mode: "replicated-job"},
		{ID: "svc-d", Name: "prune", Image: "docker:cli", Mode: "global-job", RunningTasks: intp(0), DesiredTasks: intp(0)},
		{ID: "svc-e", Name: "idle", Mode: "replicated", Replicas: intp(0)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("services =\n%+v\nwant\n%+v", got, want)
	}

	// Nothing from the container spec beyond the image leaves the host.
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"hunter2", "secret", "db_password", "cfg1", "creds", "/bin/api", "container-label", "traefik"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("payload contains %q: %s", leak, b)
		}
	}
	// replicas=0 is sent, not omitted.
	if !strings.Contains(string(b), `"replicas":0`) {
		t.Errorf("scaled-to-zero replicas missing: %s", b)
	}
}

func TestCollectSwarmServicesEmpty(t *testing.T) {
	got, truncated, err := CollectSwarmServices(context.Background(), &dockerapitest.Fake{})
	if err != nil || truncated || len(got) != 0 {
		t.Errorf("got %+v, %v, %v", got, truncated, err)
	}
}

func TestCollectSwarmServicesCaps(t *testing.T) {
	var list []swarm.Service
	for i := range MaxSwarmServices + 5 {
		list = append(list, swarm.Service{ID: fmt.Sprintf("svc%05d", MaxSwarmServices+5-i)})
	}
	got, truncated, err := CollectSwarmServices(context.Background(), &dockerapitest.Fake{Services: list})
	if err != nil || !truncated || len(got) != MaxSwarmServices {
		t.Fatalf("len=%d truncated=%v err=%v", len(got), truncated, err)
	}
	if got[0].ID != "svc00001" || got[len(got)-1].ID != fmt.Sprintf("svc%05d", MaxSwarmServices) {
		t.Errorf("not the lowest ids: first %s last %s", got[0].ID, got[len(got)-1].ID)
	}

	// A single service's ports over the cap also flags truncated.
	var ports []swarm.PortConfig
	for i := range MaxSwarmPortsPerService + 1 {
		ports = append(ports, swarm.PortConfig{Protocol: "tcp", TargetPort: uint32(20000 - i), PublishedPort: uint32(20000 - i)})
	}
	svc := swarm.Service{ID: "x", Endpoint: swarm.Endpoint{Ports: ports}}
	got, truncated, err = CollectSwarmServices(context.Background(), &dockerapitest.Fake{Services: []swarm.Service{svc}})
	if err != nil || !truncated || len(got[0].Ports) != MaxSwarmPortsPerService {
		t.Fatalf("ports=%d truncated=%v err=%v", len(got[0].Ports), truncated, err)
	}
	if got[0].Ports[0].Target != 20000-MaxSwarmPortsPerService {
		t.Errorf("ports not sorted by target before the cut: first %+v", got[0].Ports[0])
	}
}

func TestCollectSwarmServicesErrors(t *testing.T) {
	tests := []struct {
		msg  string
		want error // sentinel, or nil for a plain error
	}{
		{`Error response from daemon: This node is not a swarm manager. Worker nodes can't be used to view or modify cluster state. Please run this command on a manager node or promote the current node to a manager.`, ErrNotSwarmManager},
		{`Error response from daemon: This node is not part of a swarm`, ErrNotInSwarm},
		{`Error response from daemon: Swarm is encrypted and needs to be unlocked before it can be used. Please use "docker swarm unlock" to unlock it.`, ErrSwarmLocked},
		{`Error response from daemon: rpc error: code = Unknown desc = The swarm does not have a leader.`, nil},
		{`context deadline exceeded`, nil},
	}
	for _, tt := range tests {
		boom := errors.New(tt.msg)
		_, _, err := CollectSwarmServices(context.Background(), &dockerapitest.Fake{ServicesErr: boom})
		if !errors.Is(err, boom) || !strings.Contains(err.Error(), "docker service list") {
			t.Errorf("%q: err = %v", tt.msg, err)
		}
		for _, s := range []error{ErrNotSwarmManager, ErrNotInSwarm, ErrSwarmLocked} {
			if errors.Is(err, s) != (s == tt.want) {
				t.Errorf("%q: errors.Is(%v) = %v", tt.msg, s, !(s == tt.want))
			}
		}
	}
}
