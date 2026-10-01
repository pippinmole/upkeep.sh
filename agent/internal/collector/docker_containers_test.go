package collector

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"

	"github.com/pippinmole/upkeep.sh/agent/internal/dockerapi/dockerapitest"
)

// dockerID is a fake 64-hex-ish id that sorts by n.
func dockerID(n int) string { return fmt.Sprintf("%064x", n) }

func binding(ip, port string) network.PortBinding {
	b := network.PortBinding{HostPort: port}
	if ip != "" {
		b.HostIP = netip.MustParseAddr(ip)
	}
	return b
}

// dbInspect is a running Compose container with everything the mapping
// reads, and plenty it must not.
func dbInspect(id string) container.InspectResponse {
	return container.InspectResponse{
		ID:    id,
		Name:  "/myapp-db-1",
		Image: "sha256:img1",
		Path:  "docker-entrypoint.sh",
		Args:  []string{"postgres", "--password=hunter2"},
		State: &container.State{
			Status: container.StateRunning, Running: true,
			StartedAt: "2026-09-27T12:00:00.123456789+02:00", FinishedAt: "0001-01-01T00:00:00Z",
		},
		HostConfig: &container.HostConfig{
			NetworkMode:   "myapp_default",
			Privileged:    true,
			RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
		},
		Config: &container.Config{
			Image:      "postgres:18",
			Env:        []string{"POSTGRES_PASSWORD=hunter2"},
			Cmd:        []string{"postgres", "-c", "secret=hunter2"},
			Entrypoint: []string{"docker-entrypoint.sh"},
			Labels: map[string]string{
				"com.docker.compose.project":                    "myapp",
				"com.docker.compose.service":                    "db",
				"traefik.http.middlewares.auth.basicauth.users": "admin:$apr1$hunter2",
				"com.docker.compose.mytoken":                    "hunter2",
			},
		},
		NetworkSettings: &container.NetworkSettings{
			Ports: network.PortMap{
				network.MustParsePort("5432/tcp"): {binding("0.0.0.0", "5432"), binding("::", "5432"), binding("0.0.0.0", "5432")},
				network.MustParsePort("8080/tcp"): nil, // exposed only
				network.MustParsePort("53/udp"):   {binding("127.0.0.1", "5353")},
			},
			Networks: map[string]*network.EndpointSettings{"myapp_default": {}, "backend": {}},
		},
		Mounts: []container.MountPoint{
			{
				Type: mount.TypeVolume, Name: "cifs-creds", Source: "/var/lib/docker/volumes/cifs-creds/_data",
				Destination: "/var/lib/postgresql", Driver: "local", RW: true,
			},
			{Type: mount.TypeBind, Source: "/srv/myapp/backups", Destination: "/backups", RW: true},
			{Type: mount.TypeBind, Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock"},
		},
	}
}

func TestCollectDockerContainers(t *testing.T) {
	db, stopped := dockerID(1), dockerID(2)
	f := &dockerapitest.Fake{
		Containers: []container.Summary{
			// Out of order, to check sorting by id.
			{ID: stopped, Names: []string{"/old"}, Image: "alpine", State: container.StateExited},
			{ID: db, Names: []string{"/myapp-db-1"}, Image: "postgres:18", State: container.StateRunning},
		},
		ContainerInspects: map[string]container.InspectResponse{
			db: dbInspect(db),
			stopped: {
				ID: stopped, Name: "/old", Image: "sha256:img2",
				State:           &container.State{Status: container.StateCreated, StartedAt: "0001-01-01T00:00:00Z"},
				HostConfig:      &container.HostConfig{NetworkMode: "bridge", RestartPolicy: container.RestartPolicy{Name: "no"}},
				Config:          &container.Config{Image: "alpine:3.20"},
				NetworkSettings: &container.NetworkSettings{},
			},
		},
	}
	got, truncated, err := CollectDockerContainers(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Error("truncated, want not")
	}
	want := []DockerContainer{
		{
			ID: db, Name: "myapp-db-1", Image: "postgres:18", ImageID: "sha256:img1", State: "running",
			StartedAt: "2026-09-27T10:00:00Z",
			Labels:    map[string]string{"com.docker.compose.project": "myapp", "com.docker.compose.service": "db"},
			Ports: []DockerPort{
				{HostIP: "127.0.0.1", HostPort: 5353, ContainerPort: 53, Proto: "udp"},
				{HostIP: "0.0.0.0", HostPort: 5432, ContainerPort: 5432, Proto: "tcp"}, // duplicate reported once
				{HostIP: "::", HostPort: 5432, ContainerPort: 5432, Proto: "tcp"},
				{ContainerPort: 8080, Proto: "tcp"},
			},
			Networks:      []string{"backend", "myapp_default"},
			NetworkMode:   "myapp_default",
			Privileged:    new(true),
			RestartPolicy: "unless-stopped",
			Mounts: []DockerMount{
				{Type: "bind", Source: "/srv/myapp/backups", Destination: "/backups", RW: true},
				{Type: "volume", Destination: "/var/lib/postgresql", RW: true},
				{Type: "bind", Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock"},
			},
		},
		{
			ID: stopped, Name: "old", Image: "alpine:3.20", ImageID: "sha256:img2", State: "created",
			NetworkMode: "bridge", Privileged: new(false), RestartPolicy: "no",
		},
	}
	if !reflect.DeepEqual(got, want) {
		gb, _ := json.MarshalIndent(got, "", " ")
		t.Errorf("containers =\n%s", gb)
	}

	// Nothing the wire type doesn't declare leaks: env, command, args,
	// non-allowlisted labels, volume names and sources.
	b, _ := json.Marshal(got)
	for _, secret := range []string{"hunter2", "cifs-creds", "/var/lib/docker/volumes", "docker-entrypoint", "traefik"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("payload contains %q: %s", secret, b)
		}
	}
	if strings.Contains(string(b), `"host_port":0`) || strings.Contains(string(b), `"host_ip":""`) {
		t.Errorf("unpublished port has a host side: %s", b)
	}
}

// Only a bind mount's source is ever sent.
func TestDockerMountsSourceOnlyForBind(t *testing.T) {
	var in []container.MountPoint
	for i, typ := range []mount.Type{
		mount.TypeBind, mount.TypeVolume, mount.TypeTmpfs, mount.TypeNamedPipe,
		mount.TypeCluster, mount.TypeImage, "something-new",
	} {
		in = append(in, container.MountPoint{
			Type: typ, Name: "name", Source: "/src/" + string(typ),
			Destination: fmt.Sprintf("/d%d", i), RW: true,
		})
	}
	got, cut := dockerMounts(in)
	if cut || len(got) != len(in) {
		t.Fatalf("mounts = %+v, cut %v", got, cut)
	}
	for _, m := range got {
		if m.Type == "bind" {
			if m.Source != "/src/bind" {
				t.Errorf("bind source = %q", m.Source)
			}
		} else if m.Source != "" {
			t.Errorf("%s mount has source %q", m.Type, m.Source)
		}
	}
}

// A container removed between the list and its inspect is skipped, and
// the section is still complete (not truncated).
func TestCollectDockerContainersDisappeared(t *testing.T) {
	a, gone := dockerID(1), dockerID(2)
	f := &dockerapitest.Fake{
		Containers:        []container.Summary{{ID: a}, {ID: gone}},
		ContainerInspects: map[string]container.InspectResponse{a: {ID: a, Name: "/a"}},
	}
	got, truncated, err := CollectDockerContainers(context.Background(), f)
	if err != nil || truncated || len(got) != 1 || got[0].ID != a {
		t.Errorf("got %+v, truncated %v, err %v", got, truncated, err)
	}
}

// failingInspects fails the inspect of one id with a non-404 error and
// counts inspect calls and their concurrency.
type failingInspects struct {
	*dockerapitest.Fake
	failID          string
	failErr         error  // default: an engine error
	onFail          func() // called before failing
	calls, inFlight atomic.Int32
	mu              sync.Mutex
	maxInFlight     int32
	delay           time.Duration
	inspectedIDs    []string
}

func (f *failingInspects) track(id string) func() {
	f.calls.Add(1)
	n := f.inFlight.Add(1)
	f.mu.Lock()
	f.maxInFlight = max(f.maxInFlight, n)
	f.inspectedIDs = append(f.inspectedIDs, id)
	f.mu.Unlock()
	time.Sleep(f.delay)
	return func() { f.inFlight.Add(-1) }
}

func (f *failingInspects) ContainerInspect(ctx context.Context, id string) (container.InspectResponse, error) {
	defer f.track(id)()
	if id == f.failID {
		if f.onFail != nil {
			f.onFail()
		}
		return container.InspectResponse{}, cmp.Or(f.failErr, errors.New("Error response from daemon: boom"))
	}
	return f.Fake.ContainerInspect(ctx, id)
}

// A failed inspect (other than a 404) keeps the container as a partial
// entry from its list data, with the error, and the collector stays ok:
// dropping it would read as the container having been removed.
func TestCollectDockerContainersInspectError(t *testing.T) {
	for name, failErr := range map[string]error{
		"engine error": errors.New("Error response from daemon: boom"),
		// One call timing out while the collector's context is live is
		// about that container, not the run.
		"call timeout": fmt.Errorf("boom: %w", context.DeadlineExceeded),
	} {
		t.Run(name, func(t *testing.T) {
			f := &failingInspects{
				Fake:   &dockerapitest.Fake{ContainerInspects: map[string]container.InspectResponse{}},
				failID: dockerID(5), failErr: failErr,
			}
			for i := range 10 {
				id := dockerID(i)
				f.Containers = append(f.Containers, container.Summary{ID: id})
				f.ContainerInspects[id] = container.InspectResponse{ID: id, Name: "/full"}
			}
			f.Containers[5] = container.Summary{
				ID: dockerID(5), Names: []string{"/myapp-web-1"}, Image: "nginx:1", ImageID: "sha256:i1",
				State: container.StateRunning, Command: "nginx --token=hunter2",
				Labels: map[string]string{"com.docker.compose.service": "web", "traefik.auth": "hunter2"},
				Ports:  []container.PortSummary{{PrivatePort: 80, PublicPort: 8080, Type: "tcp"}},
			}
			got, truncated, err := CollectDockerContainers(context.Background(), f)
			if err != nil || truncated || len(got) != 10 {
				t.Fatalf("got %d containers, truncated %v, err %v", len(got), truncated, err)
			}
			want := DockerContainer{
				ID: dockerID(5), Name: "myapp-web-1", Image: "nginx:1", ImageID: "sha256:i1", State: "running",
				Labels:       map[string]string{"com.docker.compose.service": "web"},
				InspectError: failErr.Error(),
			}
			if !reflect.DeepEqual(got[5], want) {
				t.Errorf("partial = %+v\nwant %+v", got[5], want)
			}
			if got[4].Name != "full" || got[4].InspectError != "" {
				t.Errorf("full entry = %+v", got[4])
			}
			b, _ := json.Marshal(got)
			if strings.Contains(string(b), "hunter2") {
				t.Errorf("partial entry leaks: %s", b)
			}
		})
	}

	f := &dockerapitest.Fake{ContainersErr: errors.New("list boom")}
	if _, _, err := CollectDockerContainers(context.Background(), f); err == nil || !strings.Contains(err.Error(), "docker container list") {
		t.Errorf("list error = %v", err)
	}
}

// The collector's own context ending mid-run fails it: the inspect
// failures then say nothing about the containers, and an ok list of
// partial entries would be noise.
func TestCollectDockerContainersContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &failingInspects{
		Fake:   &dockerapitest.Fake{ContainerInspects: map[string]container.InspectResponse{}},
		failID: dockerID(3), failErr: context.Canceled, onFail: cancel,
	}
	for i := range 4 {
		id := dockerID(i)
		f.Containers = append(f.Containers, container.Summary{ID: id})
		f.ContainerInspects[id] = container.InspectResponse{ID: id}
	}
	if got, _, err := CollectDockerContainers(ctx, f); !errors.Is(err, context.Canceled) || got != nil {
		t.Errorf("got %+v, err %v; want context.Canceled", got, err)
	}
}

func TestDockerInspectErrorBounded(t *testing.T) {
	long := errors.New(strings.Repeat("x", DockerInspectErrorMax-1) + "é and more")
	got := dockerInspectError(long)
	if len(got) != DockerInspectErrorMax-1 || !utf8.ValidString(got) {
		t.Errorf("len %d, valid %v", len(got), utf8.ValidString(got))
	}
	if got := dockerInspectError(errors.New("short")); got != "short" {
		t.Errorf("short = %q", got)
	}
}

// Over the cap: the lowest ids are kept, only they are inspected, and at
// most dockerInspectConcurrency inspects run at once.
func TestCollectDockerContainersCap(t *testing.T) {
	f := &failingInspects{Fake: &dockerapitest.Fake{ContainerInspects: map[string]container.InspectResponse{}}}
	for i := MaxDockerContainers + 4; i >= 0; i-- {
		id := dockerID(i)
		f.Containers = append(f.Containers, container.Summary{ID: id})
		f.ContainerInspects[id] = container.InspectResponse{ID: id}
	}
	got, truncated, err := CollectDockerContainers(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || len(got) != MaxDockerContainers || got[0].ID != dockerID(0) || got[len(got)-1].ID != dockerID(MaxDockerContainers-1) {
		t.Errorf("got %d containers (%s..%s), truncated %v", len(got), got[0].ID, got[len(got)-1].ID, truncated)
	}
	if n := f.calls.Load(); n != MaxDockerContainers {
		t.Errorf("%d inspects, want %d", n, MaxDockerContainers)
	}
	if f.maxInFlight > dockerInspectConcurrency {
		t.Errorf("%d inspects in flight, want at most %d", f.maxInFlight, dockerInspectConcurrency)
	}
}

func TestCollectDockerContainersConcurrencyBound(t *testing.T) {
	f := &failingInspects{Fake: &dockerapitest.Fake{ContainerInspects: map[string]container.InspectResponse{}}, delay: 5 * time.Millisecond}
	for i := range 20 {
		id := dockerID(i)
		f.Containers = append(f.Containers, container.Summary{ID: id})
		f.ContainerInspects[id] = container.InspectResponse{ID: id}
	}
	if _, _, err := CollectDockerContainers(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if f.maxInFlight < 2 || f.maxInFlight > dockerInspectConcurrency {
		t.Errorf("max in flight = %d, want 2..%d", f.maxInFlight, dockerInspectConcurrency)
	}
}

// A cancelled context fails the collector rather than returning a partial
// list.
func TestCollectDockerContainersCancelled(t *testing.T) {
	f := &dockerapitest.Fake{ContainerInspects: map[string]container.InspectResponse{}}
	for i := range 20 {
		id := dockerID(i)
		f.Containers = append(f.Containers, container.Summary{ID: id})
		f.ContainerInspects[id] = container.InspectResponse{ID: id}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, _, err := CollectDockerContainers(ctx, f); !errors.Is(err, context.Canceled) || got != nil {
		t.Errorf("got %+v, err %v; want context.Canceled", got, err)
	}
}

// Per-item caps flag the collector truncated and keep a sorted prefix.
func TestDockerContainerPerItemCaps(t *testing.T) {
	// A published range "8000-8199:8000-8199" expands to one entry per port.
	pm := network.PortMap{}
	for p := 8000; p < 8200; p++ {
		pm[network.MustParsePort(fmt.Sprintf("%d/tcp", p))] = []network.PortBinding{binding("0.0.0.0", fmt.Sprint(p))}
	}
	ports, cut := dockerPorts(pm)
	if !cut || len(ports) != MaxDockerPortsPerContainer || ports[0].ContainerPort != 8000 || ports[len(ports)-1].ContainerPort != 8099 {
		t.Errorf("ports: %d, cut %v, %+v..%+v", len(ports), cut, ports[0], ports[len(ports)-1])
	}

	nets := map[string]*network.EndpointSettings{}
	for i := range MaxDockerNetworksPerContainer + 1 {
		nets[fmt.Sprintf("net%03d", i)] = nil
	}
	names, cut := dockerNetworkNames(nets)
	if !cut || len(names) != MaxDockerNetworksPerContainer || names[0] != "net000" {
		t.Errorf("networks: %d, cut %v", len(names), cut)
	}

	var mounts []container.MountPoint
	for i := range MaxDockerMountsPerContainer + 1 {
		mounts = append(mounts, container.MountPoint{Type: mount.TypeTmpfs, Destination: fmt.Sprintf("/m%03d", i)})
	}
	ms, cut := dockerMounts(mounts)
	if !cut || len(ms) != MaxDockerMountsPerContainer || ms[0].Destination != "/m000" {
		t.Errorf("mounts: %d, cut %v", len(ms), cut)
	}

	f := &dockerapitest.Fake{
		Containers:        []container.Summary{{ID: "a"}},
		ContainerInspects: map[string]container.InspectResponse{"a": {ID: "a", NetworkSettings: &container.NetworkSettings{Ports: pm}}},
	}
	if _, truncated, err := CollectDockerContainers(context.Background(), f); err != nil || !truncated {
		t.Errorf("truncated %v, err %v; want truncated", truncated, err)
	}
}

func TestDockerTime(t *testing.T) {
	for in, want := range map[string]string{
		"2026-09-27T12:00:00.123456789+02:00": "2026-09-27T10:00:00Z",
		"2026-09-27T10:00:00Z":                "2026-09-27T10:00:00Z",
		"1970-01-01T00:00:00Z":                "1970-01-01T00:00:00Z",
		"0001-01-01T00:00:00Z":                "",
		"":                                    "",
		"garbage":                             "",
	} {
		if got := dockerTime(in); got != want {
			t.Errorf("dockerTime(%q) = %q, want %q", in, got, want)
		}
	}
}
