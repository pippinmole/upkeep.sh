package ingest

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

const dockerPayload = `{"schema_version": 1, ` + jammy + `,
	"collectors": {
		"docker_engine": {"status": "ok"},
		"docker_containers": {"status": "ok"},
		"docker_images": {"status": "ok", "truncated": true},
		"docker_networks": {"status": "ok"},
		"swarm_services": {"status": "ok"}
	},
	"docker": {
		"engine": {"version": "29.8.0", "api_version": "1.56", "storage_driver": "overlayfs", "image_store": "bogus", "rootless": true},
		"swarm": {"state": "active", "node_id": "n1", "cluster_id": "c1", "role": "manager"},
		"containers": [
			{"id": "c2", "name": "b", "image": "nginx", "image_id": "sha256:i", "state": "running",
			 "labels": {"com.docker.stack.namespace": "web", "com.docker.swarm.service.id": "s1", "com.docker.swarm.task.id": "t1"},
			 "ports": [{"container_port": 80, "proto": "tcp", "host_ip": "::", "host_port": 8080},
			           {"container_port": 80, "proto": "tcp", "host_ip": "0.0.0.0", "host_port": 8080},
			           {"container_port": 80, "proto": "tcp", "host_ip": "0.0.0.0", "host_port": 8080},
			           {"container_port": 0, "proto": "tcp"}, {"container_port": 53, "proto": "icmp"}],
			 "networks": ["z", "a", "a"], "privileged": false,
			 "mounts": [{"type": "volume", "source": "creds=secret", "destination": "/data", "rw": true},
			            {"type": "bind", "source": "/", "destination": "/host", "rw": false}]},
			{"id": "c1", "name": "a", "state": "exited", "inspect_error": "boom", "started_at": "2026-01-01T00:00:00Z",
			 "privileged": true, "ports": [{"container_port": 1, "proto": "tcp"}]},
			{"id": "", "name": "no id"}
		],
		"images": [
			{"id": "sha256:i", "repo_tags": ["nginx:1", "nginx:latest"], "os": "linux", "arch": "amd64",
			 "created": "2026-01-01T00:00:00Z", "layers": ["sha256:b", "sha256:a"]},
			{"id": "sha256:p", "repo_tags": ["x:1"], "os": "linux", "inspect_error": "boom"}
		],
		"networks": [{"id": "n", "name": "bridge", "driver": "bridge", "scope": "local"}],
		"swarm_services": [{"id": "s1", "name": "web_api", "image": "api:1", "mode": "replicated", "replicas": 2,
			"running_tasks": 1, "desired_tasks": 2, "labels": {"com.docker.stack.namespace": "web"},
			"ports": [{"published": 443, "target": 8443, "proto": "tcp", "publish_mode": "ingress"}]}],
		"unknown_member": {"env": "SECRET=1"}
	}
}`

func TestPlanDocker(t *testing.T) {
	plan := planDocker(decode(t, dockerPayload))
	if len(plan.notes) != 0 {
		t.Errorf("notes = %v", plan.notes)
	}
	got := kinds(plan.sets)
	ctrs, imgs := got[KindDockerContainers], got[KindDockerImages]
	if len(got) != 2 || ctrs.Additive || !imgs.Additive {
		t.Fatalf("sets = %+v", got)
	}

	if len(ctrs.Rows) != 2 || ctrs.Rows[0].Key != "c1" || ctrs.Rows[1].Key != "c2" {
		t.Fatalf("container rows = %+v", ctrs.Rows)
	}
	// Partial: nothing from inspect is used, not even what was sent;
	// started_at is unknown (nil = keep stored).
	c1 := ctrs.Rows[0]
	if !c1.Partial || c1.Detail != nil || c1.Live[0] != nil || c1.Live[1] != "boom" {
		t.Errorf("partial c1 = %+v", c1)
	}
	c2 := ctrs.Rows[1]
	if c2.Partial || c2.Values[7] != "web" || c2.Values[8] != "s1" || c2.Values[10] != "t1" || c2.Values[5] != nil {
		t.Errorf("c2 values = %#v", c2.Values)
	}
	wantPorts := []containerPort{{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80, Proto: "tcp"}, {HostIP: "::", HostPort: 8080, ContainerPort: 80, Proto: "tcp"}}
	if !reflect.DeepEqual(c2.Detail[0], wantPorts) {
		t.Errorf("ports = %#v", c2.Detail[0])
	}
	if !reflect.DeepEqual(c2.Detail[1], []string{"a", "z"}) || c2.Detail[3] != false || c2.Detail[2] != nil {
		t.Errorf("c2 detail = %#v", c2.Detail)
	}
	wantMounts := []containerMount{{Type: "volume", Destination: "/data", RW: true}, {Type: "bind", Source: "/", Destination: "/host"}}
	if !reflect.DeepEqual(c2.Detail[5], wantMounts) {
		t.Errorf("mounts (volume source must be dropped) = %#v", c2.Detail[5])
	}

	if len(imgs.Rows) != 2 || imgs.Rows[1].Partial != true || imgs.Rows[0].Partial {
		t.Fatalf("image rows = %+v", imgs.Rows)
	}
	if len(plan.images) != 1 || plan.images[0].ImageID != "sha256:i" || plan.images[0].Created == nil ||
		!plan.images[0].Created.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) ||
		!reflect.DeepEqual(plan.images[0].Layers, []string{"sha256:b", "sha256:a"}) {
		t.Errorf("image content = %+v (partial images must not be interned; layers keep chain order)", plan.images)
	}

	if e := plan.engine; e == nil || e.ImageStore != "" || !e.Rootless || e.Swarm == nil || e.Swarm.ClusterID != "c1" {
		t.Errorf("engine = %+v", plan.engine)
	}
	if plan.networks == nil || plan.networks.Truncated {
		t.Errorf("networks = %+v", plan.networks)
	}
	if sw := plan.swarm; sw == nil || sw.ClusterID != "c1" || len(sw.Set.Rows) != 1 ||
		sw.Set.Rows[0].Values[5] != "web" || sw.Set.Rows[0].Live[0] != 1 {
		t.Errorf("swarm = %+v", plan.swarm)
	}
}

// Only ok collectors contribute; remote hosts, unmounted sockets, errors
// and legacy payloads leave everything stored untouched.
func TestPlanDockerAuthority(t *testing.T) {
	for name, collectors := range map[string]string{
		"remote host": `"docker_engine": {"status": "skipped", "reason": "remote host"},
			"docker_containers": {"status": "skipped", "reason": "remote host"},
			"docker_images": {"status": "skipped", "reason": "remote host"},
			"docker_networks": {"status": "skipped", "reason": "remote host"},
			"swarm_services": {"status": "skipped", "reason": "remote host"}`,
		"socket not mounted": `"docker_engine": {"status": "skipped", "reason": "docker socket not mounted"},
			"docker_containers": {"status": "skipped", "reason": "docker socket not mounted"}`,
		"engine error": `"docker_engine": {"status": "error", "error": "refused"},
			"docker_containers": {"status": "skipped", "reason": "docker engine unavailable"},
			"swarm_services": {"status": "skipped", "reason": "docker engine unavailable"}`,
		"containers timed out": `"docker_containers": {"status": "error", "error": "deadline"}`,
	} {
		p := decode(t, `{"schema_version": 1, "collectors": {`+collectors+`},
			"docker": {"containers": [{"id": "c1"}], "images": [{"id": "i"}], "swarm_services": [{"id": "s", "name": "s"}],
			           "engine": {"version": "1"}, "swarm": {"state": "active", "cluster_id": "c", "role": "manager"}}}`)
		plan := planDocker(p)
		if len(plan.sets) != 0 || plan.engine != nil || plan.networks != nil || plan.swarm != nil || plan.images != nil {
			t.Errorf("%s: plan = %+v", name, plan)
		}
	}

	// Legacy (no collectors map): never authoritative for Docker.
	if plan := planDocker(decode(t, `{"schema_version": 1, "docker": {"containers": [{"id": "c1"}]}}`)); len(plan.sets) != 0 {
		t.Errorf("legacy plan = %+v", plan)
	}

	// ok and empty: an authoritative empty set (closes everything).
	plan := planDocker(decode(t, `{"schema_version": 1, "collectors": {"docker_containers": {"status": "ok"}}}`))
	if s := kinds(plan.sets)[KindDockerContainers]; len(plan.sets) != 1 || len(s.Rows) != 0 || s.Additive {
		t.Errorf("ok-and-empty = %+v", plan.sets)
	}

	// A malformed block drops Docker, not the push.
	p := decode(t, `{"schema_version": 1, "collectors": {"docker_containers": {"status": "ok"}}, "docker": {"containers": "nope"}}`)
	if plan := planDocker(p); len(plan.sets) != 0 || len(plan.notes) != 1 || !strings.Contains(plan.notes[0], "docker block dropped") {
		t.Errorf("malformed plan = %+v", plan)
	}
	if in := buildSnapshotInput(p, "a", time.Now(), time.Now(), ""); len(in.FactSets) != 0 {
		t.Errorf("malformed block produced fact sets: %+v", in.FactSets)
	}
}

// swarm_services are applied only from an active manager with a cluster id.
func TestPlanDockerSwarmGate(t *testing.T) {
	for name, tc := range map[string]struct {
		engine, swarm string
		want          bool
	}{
		"manager":        {`{"status": "ok"}`, `{"state": "active", "node_id": "n", "cluster_id": "c", "role": "manager"}`, true},
		"worker":         {`{"status": "ok"}`, `{"state": "active", "node_id": "n", "cluster_id": "c", "role": "worker"}`, false},
		"no cluster id":  {`{"status": "ok"}`, `{"state": "active", "node_id": "n", "role": "manager"}`, false},
		"locked":         {`{"status": "ok"}`, `{"state": "locked"}`, false},
		"engine not ok":  {`{"status": "error"}`, `{"state": "active", "node_id": "n", "cluster_id": "c", "role": "manager"}`, false},
		"no swarm block": {`{"status": "ok"}`, `null`, false},
		"unknown state":  {`{"status": "ok"}`, `{"state": "pending", "cluster_id": "c", "role": "manager"}`, false},
	} {
		p := decode(t, `{"schema_version": 1, "collectors": {"docker_engine": `+tc.engine+`, "swarm_services": {"status": "ok"}},
			"docker": {"engine": {"version": "1"}, "swarm": `+tc.swarm+`, "swarm_services": [{"id": "s", "name": "s"}]}}`)
		if got := planDocker(p).swarm != nil; got != tc.want {
			t.Errorf("%s: swarm applied = %v, want %v", name, got, tc.want)
		}
	}
}
