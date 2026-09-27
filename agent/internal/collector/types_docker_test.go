package collector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func TestFilterDockerLabels(t *testing.T) {
	allowed := map[string]string{
		"com.docker.compose.project":                  "myapp",
		"com.docker.compose.service":                  "db",
		"com.docker.compose.container-number":         "1",
		"com.docker.compose.oneoff":                   "False",
		"com.docker.compose.version":                  "2.39.0",
		"com.docker.compose.config-hash":              "abc",
		"com.docker.compose.depends_on":               "cache:service_started:false",
		"com.docker.compose.image":                    "sha256:aa",
		"com.docker.compose.replace":                  "myapp-db-1",
		"com.docker.compose.project.config_files":     "/srv/myapp/compose.yml",
		"com.docker.compose.project.working_dir":      "/srv/myapp",
		"com.docker.compose.project.environment_file": "/srv/myapp/.env",
		"com.docker.stack.namespace":                  "web",
		"com.docker.stack.image":                      "ghcr.io/me/api:1",
		"com.docker.swarm.node.id":                    "n1",
		"com.docker.swarm.service.id":                 "s1",
		"com.docker.swarm.service.name":               "web_api",
		"com.docker.swarm.task.id":                    "t1",
		"com.docker.swarm.task.name":                  "web_api.1.t1",
		"org.opencontainers.image.version":            "18.0",
		"org.opencontainers.image.anything-new":       "x", // OCI is a prefix match
	}
	in := map[string]string{
		// User-chosen keys under Docker-owned prefixes: exact keys only.
		"com.docker.compose.mytoken":   "s3cret",
		"com.docker.stack.password":    "s3cret",
		"com.docker.swarm.custom":      "s3cret",
		"com.docker.compose.project.x": "no",
		// Everything else.
		"traefik.http.middlewares.a.basicauth.users": "admin:$apr1$secret",
		"com.docker.composeX":                        "no",
		"com.docker.compose.":                        "no",
		"COM.DOCKER.COMPOSE.PROJECT":                 "no", // case-sensitive
		"xcom.docker.compose.project":                "no",
		"org.opencontainers.image.":                  "no", // empty suffix
		"org.opencontainers.imageX.version":          "no",
		"coolify.managed":                            "true",
		"":                                           "no",
	}
	for k, v := range allowed {
		in[k] = v
	}
	if got := FilterDockerLabels(in); !reflect.DeepEqual(got, allowed) {
		t.Errorf("FilterDockerLabels = %v, want %v", got, allowed)
	}
}

func TestFilterDockerLabelsNil(t *testing.T) {
	for name, in := range map[string]map[string]string{
		"nil":          nil,
		"empty":        {},
		"none allowed": {"traefik.enable": "true", "com.docker.composeX": "x"},
	} {
		if got := FilterDockerLabels(in); got != nil {
			t.Errorf("%s: FilterDockerLabels = %#v, want nil", name, got)
		}
	}
}

func TestFilterDockerLabelsCap(t *testing.T) {
	in := map[string]string{"unrelated": "x"}
	for i := 0; i < MaxDockerLabels+10; i++ {
		in[fmt.Sprintf("org.opencontainers.image.k%03d", i)] = "v"
	}
	got := FilterDockerLabels(in)
	if len(got) != MaxDockerLabels {
		t.Fatalf("kept %d labels, want %d", len(got), MaxDockerLabels)
	}
	// Deterministic: the lexically first keys survive.
	for i := 0; i < MaxDockerLabels; i++ {
		if _, ok := got[fmt.Sprintf("org.opencontainers.image.k%03d", i)]; !ok {
			t.Fatalf("key k%03d missing from capped labels", i)
		}
	}
}

// TestDockerJSON pins the docker block's wire names to the PROTOCOL.md
// sketch: a fully populated block serializes to exactly these keys.
func TestDockerJSON(t *testing.T) {
	two := 2
	d := &Docker{
		Engine: &DockerEngine{Version: "29.8.0", APIVersion: "1.56",
			StorageDriver: "overlayfs", ImageStore: "containerd", Rootless: false},
		Swarm: &DockerSwarm{NodeID: "n1", ClusterID: "c1", Role: "manager"},
		Containers: []DockerContainer{{
			ID: "8e89", Name: "myapp-db-1", Image: "postgres:18", ImageID: "sha256:aa",
			State: "running", StartedAt: "2026-09-27T10:00:00Z",
			Labels: map[string]string{"com.docker.compose.project": "myapp"},
			Ports: []DockerPort{{HostIP: "0.0.0.0", HostPort: 5432,
				ContainerPort: 5432, Proto: "tcp"}},
			Networks: []string{"myapp_default"}, NetworkMode: "bridge",
			Privileged: false, RestartPolicy: "unless-stopped",
			Mounts: []DockerMount{
				{Type: "volume", Destination: "/var/lib/postgresql", RW: true},
				{Type: "bind", Source: "/var/run/docker.sock",
					Destination: "/var/run/docker.sock", RW: false},
			},
		}},
		Images: []DockerImage{{
			ID: "sha256:aa", RepoTags: []string{"postgres:18"},
			RepoDigests: []string{"postgres@sha256:bb"}, Created: "2026-09-01T00:00:00Z",
			OS: "linux", Arch: "amd64", Layers: []string{"sha256:cc"},
			Labels: map[string]string{"org.opencontainers.image.version": "18.0"},
		}},
		Networks: []DockerNetwork{{ID: "n", Name: "myapp_default", Driver: "bridge",
			Scope: "local", Internal: false, Subnets: []string{"172.18.0.0/16"}}},
		SwarmServices: []SwarmService{{
			ID: "s", Name: "web_api", Image: "ghcr.io/me/api:1@sha256:dd",
			Mode: "replicated", Replicas: &two,
			Labels: map[string]string{"com.docker.stack.namespace": "web"},
			Ports: []SwarmPort{{Published: 443, Target: 8443, Proto: "tcp",
				PublishMode: "ingress"}},
		}},
	}
	got, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{` +
		`"engine":{"version":"29.8.0","api_version":"1.56","storage_driver":"overlayfs","image_store":"containerd","rootless":false},` +
		`"swarm":{"node_id":"n1","cluster_id":"c1","role":"manager"},` +
		`"containers":[{"id":"8e89","name":"myapp-db-1","image":"postgres:18","image_id":"sha256:aa","state":"running",` +
		`"started_at":"2026-09-27T10:00:00Z","labels":{"com.docker.compose.project":"myapp"},` +
		`"ports":[{"host_ip":"0.0.0.0","host_port":5432,"container_port":5432,"proto":"tcp"}],` +
		`"networks":["myapp_default"],"network_mode":"bridge","privileged":false,"restart_policy":"unless-stopped",` +
		`"mounts":[{"type":"volume","destination":"/var/lib/postgresql","rw":true},` +
		`{"type":"bind","source":"/var/run/docker.sock","destination":"/var/run/docker.sock","rw":false}]}],` +
		`"images":[{"id":"sha256:aa","repo_tags":["postgres:18"],"repo_digests":["postgres@sha256:bb"],` +
		`"created":"2026-09-01T00:00:00Z","os":"linux","arch":"amd64","layers":["sha256:cc"],` +
		`"labels":{"org.opencontainers.image.version":"18.0"}}],` +
		`"networks":[{"id":"n","name":"myapp_default","driver":"bridge","scope":"local","internal":false,"subnets":["172.18.0.0/16"]}],` +
		`"swarm_services":[{"id":"s","name":"web_api","image":"ghcr.io/me/api:1@sha256:dd","mode":"replicated","replicas":2,` +
		`"labels":{"com.docker.stack.namespace":"web"},` +
		`"ports":[{"published":443,"target":8443,"proto":"tcp","publish_mode":"ingress"}]}]` +
		`}`
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("docker JSON mismatch\n got: %s\nwant: %s", got, want)
	}

	// Round-trip: nothing is lost or renamed.
	var back Docker
	if err := json.Unmarshal(got, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&back, d) {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", back, *d)
	}
}

// TestDockerJSONOmissions: members owned by a collector that isn't ok are
// absent, zero-replica services keep their count, and unpublished ports
// have no host side.
func TestDockerJSONOmissions(t *testing.T) {
	zero := 0
	for name, tc := range map[string]struct {
		v    any
		want string
	}{
		"empty block":      {&Docker{}, `{}`},
		"no docker":        {Snapshot{}, ""}, // checked below: no "docker" key
		"scaled to zero":   {SwarmService{Replicas: &zero}, `{"id":"","name":"","image":"","mode":"","replicas":0}`},
		"global service":   {SwarmService{Mode: "global"}, `{"id":"","name":"","image":"","mode":"global"}`},
		"unpublished port": {DockerPort{ContainerPort: 80, Proto: "tcp"}, `{"container_port":80,"proto":"tcp"}`},
	} {
		got, err := json.Marshal(tc.v)
		if err != nil {
			t.Fatal(err)
		}
		if name == "no docker" {
			if bytes.Contains(got, []byte(`"docker"`)) {
				t.Errorf("%s: snapshot without Docker serialized a docker key: %s", name, got)
			}
			continue
		}
		if string(got) != tc.want {
			t.Errorf("%s: got %s, want %s", name, got, tc.want)
		}
	}
}
