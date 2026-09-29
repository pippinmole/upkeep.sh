package ingest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

// End-to-end Docker ingest: payload JSON -> buildSnapshotInput ->
// store.InsertSnapshot, against SW_TEST_DATABASE_URL.

type dockerEnv struct {
	t  *testing.T
	s  *store.Store
	t0 time.Time
}

func newDockerEnv(t *testing.T) *dockerEnv {
	t.Helper()
	dsn := os.Getenv("SW_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SW_TEST_DATABASE_URL not set")
	}
	s, err := store.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// container_images is fleet-wide (no user to cascade from).
		_, _ = s.Pool.Exec(context.Background(), `DELETE FROM container_images WHERE image_id IN ($1, $2)`, img1, img2)
		s.Close()
	})
	return &dockerEnv{t: t, s: s, t0: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)}
}

// user creates a user (deleted at cleanup, cascading to hosts, ranges and
// clusters) and returns its id.
func (e *dockerEnv) user() string {
	e.t.Helper()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	ctx := context.Background()
	var id string
	if err := e.s.Pool.QueryRow(ctx, `INSERT INTO users (email) VALUES ($1) RETURNING id`,
		"swtest-"+hex.EncodeToString(b)+"@test.invalid").Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _, _ = e.s.Pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id) })
	return id
}

func (e *dockerEnv) host(userID, name string) string {
	e.t.Helper()
	id, err := e.s.CreateHost(context.Background(), userID, name)
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

// push ingests a payload with the given collectors and docker block at
// t0 + minute.
func (e *dockerEnv) push(hostID string, minute int, collectors map[string]any, docker map[string]any) store.SnapshotResult {
	e.t.Helper()
	at := e.t0.Add(time.Duration(minute) * time.Minute)
	body, _ := json.Marshal(map[string]any{
		"schema_version": 1, "collected_at": at.Format(time.RFC3339),
		"os":         map[string]any{"id": "ubuntu", "version_id": "24.04", "codename": "noble"},
		"collectors": collectors, "docker": docker,
	})
	var p SnapshotPayload
	if err := json.Unmarshal(body, &p); err != nil {
		e.t.Fatal(err)
	}
	in := buildSnapshotInput(p, "", at, at.Add(time.Hour), "203.0.113.9")
	in.AgentID, in.HostID = "", hostID
	res, err := e.s.InsertSnapshot(context.Background(), in)
	if err != nil {
		e.t.Fatalf("push at +%dm: %v", minute, err)
	}
	return res
}

func stOK() map[string]any        { return map[string]any{"status": "ok"} }
func okTruncated() map[string]any { return map[string]any{"status": "ok", "truncated": true} }
func skipped(reason string) map[string]any {
	return map[string]any{"status": "skipped", "reason": reason}
}

func allDocker(status map[string]any) map[string]any {
	return map[string]any{"docker_engine": status, "docker_containers": status, "docker_images": status,
		"docker_networks": status, "swarm_services": skipped("not in a swarm")}
}

const (
	cDB  = "aaaa000000000000000000000000000000000000000000000000000000000001"
	cWeb = "aaaa000000000000000000000000000000000000000000000000000000000002"
	img1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	img2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func dbContainer(state, startedAt string) map[string]any {
	return map[string]any{
		"id": cDB, "name": "myapp-db-1", "image": "postgres:18", "image_id": img1, "state": state,
		"started_at": startedAt,
		"labels":     map[string]any{"com.docker.compose.project": "myapp", "com.docker.compose.service": "db"},
		"ports": []any{
			map[string]any{"host_ip": "0.0.0.0", "host_port": 5432, "container_port": 5432, "proto": "tcp"},
			map[string]any{"container_port": 9999, "proto": "tcp"},
		},
		"networks": []any{"myapp_default"}, "network_mode": "bridge", "privileged": true,
		"restart_policy": "unless-stopped",
		"mounts": []any{
			map[string]any{"type": "bind", "source": "/var/run/docker.sock", "destination": "/var/run/docker.sock", "rw": true},
			map[string]any{"type": "volume", "source": "secret-volume-name", "destination": "/var/lib/postgresql", "rw": true},
		},
	}
}

func partialContainer(id, state string) map[string]any {
	return map[string]any{"id": id, "name": "myapp-db-1", "image": "postgres:18", "image_id": img1, "state": state,
		"labels":        map[string]any{"com.docker.compose.project": "myapp", "com.docker.compose.service": "db"},
		"inspect_error": "inspect: boom",
		// Sent by a broken agent on a partial entry: ignored (unknown).
		"privileged": false, "ports": []any{}}
}

func webContainer(startedAt string) map[string]any {
	return map[string]any{"id": cWeb, "name": "web", "image": "nginx", "image_id": img2, "state": "running",
		"started_at": startedAt, "network_mode": "host", "privileged": false, "restart_policy": "always"}
}

type ctrRange struct {
	Key, State             string
	First, Removed         int // minutes after t0; -1 = open
	Privileged             *bool
	Ports, Mounts, InspErr string
	StartedAt              string
}

func (e *dockerEnv) containers(hostID string) []ctrRange {
	e.t.Helper()
	rows, err := e.s.Pool.Query(context.Background(), `
		SELECT row_key, coalesce(state, ''), first_seen_at, removed_at, privileged,
		       coalesce(ports::text, ''), coalesce(mounts::text, ''), coalesce(inspect_error, ''),
		       coalesce(to_char(started_at AT TIME ZONE 'UTC', 'HH24:MI'), '')
		FROM host_containers WHERE host_id = $1 ORDER BY row_key, first_seen_at`, hostID)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var out []ctrRange
	for rows.Next() {
		var r ctrRange
		var first time.Time
		var removed *time.Time
		if err := rows.Scan(&r.Key, &r.State, &first, &removed, &r.Privileged, &r.Ports, &r.Mounts, &r.InspErr, &r.StartedAt); err != nil {
			e.t.Fatal(err)
		}
		r.Key = r.Key[len(r.Key)-1:]
		r.First, r.Removed = int(first.Sub(e.t0).Minutes()), -1
		if removed != nil {
			r.Removed = int(removed.Sub(e.t0).Minutes())
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func bp(b bool) *bool { return &b }

const (
	dbPorts  = `[{"proto": "tcp", "host_ip": "0.0.0.0", "host_port": 5432, "container_port": 5432}, {"proto": "tcp", "container_port": 9999}]`
	dbMounts = `[{"rw": true, "type": "volume", "destination": "/var/lib/postgresql"}, {"rw": true, "type": "bind", "source": "/var/run/docker.sock", "destination": "/var/run/docker.sock"}]`
)

func (e *dockerEnv) wantContainers(hostID string, want ...ctrRange) {
	e.t.Helper()
	got := e.containers(hostID)
	if len(got) != len(want) {
		e.t.Fatalf("containers:\n got %+v\nwant %+v", got, want)
	}
	for i := range got {
		g, w := got[i], want[i]
		if !reflect.DeepEqual(g, w) {
			e.t.Errorf("container range %d:\n got %+v (privileged %v)\nwant %+v (privileged %v)", i, g, derefBool(g.Privileged), w, derefBool(w.Privileged))
		}
	}
}

func derefBool(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

func TestDockerIngestContainers(t *testing.T) {
	e := newDockerEnv(t)
	u := e.user()
	h := e.host(u, "docker-host")
	ctx := context.Background()

	// First push opens ranges; the volume's source is never stored.
	e.push(h, 0, allDocker(stOK()), map[string]any{
		"engine":     map[string]any{"version": "29.8.0", "api_version": "1.56", "storage_driver": "overlayfs", "image_store": "containerd", "rootless": false},
		"containers": []any{dbContainer("running", "2026-03-01T00:00:00Z"), webContainer("2026-03-01T00:00:00Z")},
		"images": []any{
			map[string]any{"id": img1, "repo_tags": []any{"postgres:18"}, "repo_digests": []any{"postgres@sha256:ab"},
				"created": "2026-02-01T00:00:00Z", "os": "linux", "arch": "arm", "variant": "v7", "layers": []any{"sha256:l1", "sha256:l0"},
				"labels": map[string]any{"org.opencontainers.image.version": "18.0"}},
			map[string]any{"id": img2, "repo_tags": []any{"nginx:latest"}, "inspect_error": "boom"},
		},
		"networks": []any{map[string]any{"id": "n1", "name": "myapp_default", "driver": "bridge", "scope": "local", "subnets": []any{"172.18.0.0/16"}}},
	})
	db0 := ctrRange{Key: "1", State: "running", First: 0, Removed: -1, Privileged: bp(true), Ports: dbPorts, Mounts: dbMounts, StartedAt: "00:00"}
	web0 := ctrRange{Key: "2", State: "running", First: 0, Removed: -1, Privileged: bp(false), Ports: "[]", Mounts: "[]", StartedAt: "00:00"}
	e.wantContainers(h, db0, web0)

	var project, service *string
	if err := e.s.Pool.QueryRow(ctx, `SELECT compose_project, compose_service FROM host_containers WHERE host_id = $1 AND row_key = $2`,
		h, cDB).Scan(&project, &service); err != nil || project == nil || *project != "myapp" || *service != "db" {
		t.Errorf("compose columns: %v %v %v", project, service, err)
	}

	// Images: img1 interned and joinable; img2 (partial) present on the host
	// with unknown platform.
	var layers []string
	var arch string
	if err := e.s.Pool.QueryRow(ctx, `
		SELECT ci.layers, ci.arch FROM host_images hi JOIN container_images ci USING (image_id, os, arch, variant)
		WHERE hi.host_id = $1 AND hi.removed_at IS NULL AND hi.image_id = $2`, h, img1).Scan(&layers, &arch); err != nil ||
		!reflect.DeepEqual(layers, []string{"sha256:l1", "sha256:l0"}) || arch != "arm" {
		t.Errorf("img1 content: %v %q %v", layers, arch, err)
	}
	var os2 *string
	var ie2 *string
	if err := e.s.Pool.QueryRow(ctx, `SELECT os, inspect_error FROM host_images WHERE host_id = $1 AND image_id = $2 AND removed_at IS NULL`,
		h, img2).Scan(&os2, &ie2); err != nil || os2 != nil || ie2 == nil {
		t.Errorf("img2 partial: os=%v err=%v %v", os2, ie2, err)
	}
	var engine, store_ string
	var nets string
	if err := e.s.Pool.QueryRow(ctx, `SELECT engine_version, image_store, networks::text FROM host_docker WHERE host_id = $1`, h).
		Scan(&engine, &store_, &nets); err != nil || engine != "29.8.0" || store_ != "containerd" || nets == "" {
		t.Errorf("host_docker: %q %q %q %v", engine, store_, nets, err)
	}

	// +1: db's inspect fails, same state: the range stays as it was
	// (privileged, ports, mounts, started_at kept); inspect_error is set in
	// place.
	res := e.push(h, 1, map[string]any{"docker_containers": stOK()}, map[string]any{
		"containers": []any{partialContainer(cDB, "running"), webContainer("2026-03-01T00:00:00Z")},
	})
	if res.ImageUseChanged() { // live columns only: no image findings reconcile
		t.Errorf("in-place update reported as an image use change: %+v", res.Facts)
	}
	db1 := db0
	db1.InspErr = "inspect: boom"
	e.wantContainers(h, db1, web0)

	// +2: still partial but now exited: a new range, carrying the last known
	// detail and start time.
	e.push(h, 2, map[string]any{"docker_containers": stOK()}, map[string]any{
		"containers": []any{partialContainer(cDB, "exited"), webContainer("2026-03-01T00:00:00Z")},
	})
	db1c := db1
	db1c.Removed = 2
	db2 := db1
	db2.State, db2.First = "exited", 2
	e.wantContainers(h, db1c, db2, web0)

	// +3: collector skipped (socket unmounted) and error: nothing closes.
	e.push(h, 3, allDocker(skipped("docker socket not mounted")), map[string]any{})
	e.push(h, 4, map[string]any{"docker_engine": map[string]any{"status": "error", "error": "refused"},
		"docker_containers": skipped("docker engine unavailable")}, nil)
	e.wantContainers(h, db1c, db2, web0)

	// +5: truncated list without db: db stays open.
	e.push(h, 5, map[string]any{"docker_containers": okTruncated()}, map[string]any{
		"containers": []any{webContainer("2026-03-01T00:00:00Z")},
	})
	e.wantContainers(h, db1c, db2, web0)

	// +6: full list, db gone, web restarted (same state): db closes, web's
	// range is updated in place.
	e.push(h, 6, map[string]any{"docker_containers": stOK()}, map[string]any{
		"containers": []any{webContainer("2026-03-01T00:05:00Z")},
	})
	db2c := db2
	db2c.Removed = 6
	web6 := web0
	web6.StartedAt = "00:05"
	e.wantContainers(h, db1c, db2c, web6)

	// +7: db comes back fully inspected after a partial-only history: its
	// detail is known again. ok and empty images closes both images.
	res = e.push(h, 7, map[string]any{"docker_containers": stOK(), "docker_images": stOK()}, map[string]any{
		"containers": []any{dbContainer("running", "2026-03-01T00:07:00Z"), webContainer("2026-03-01T00:05:00Z")},
	})
	if !res.ImageUseChanged() { // queues reconcile_host (jobs.EnqueueAfterIngest)
		t.Errorf("ranges opened/closed but ImageUseChanged is false: %+v", res.Facts)
	}
	for _, f := range res.Facts {
		if f.Kind == KindDockerImages && f.Closed != 2 {
			t.Errorf("images result %+v, want 2 closed", f)
		}
	}
	db7 := db0
	db7.First, db7.StartedAt = 7, "00:07"
	e.wantContainers(h, db1c, db2c, db7, web6)

	// Unchanged push short-circuits on the set hash.
	res = e.push(h, 8, map[string]any{"docker_containers": stOK()}, map[string]any{
		"containers": []any{webContainer("2026-03-01T00:05:00Z"), dbContainer("running", "2026-03-01T00:07:00Z")},
	})
	if len(res.Facts) != 1 || res.Facts[0].Outcome != store.InventoryUnchanged || res.ImageUseChanged() {
		t.Errorf("identical push: %+v", res.Facts)
	}
}

// A partial image keeps the platform it had: host_images still joins its
// content.
func TestDockerIngestPartialImage(t *testing.T) {
	e := newDockerEnv(t)
	h := e.host(e.user(), "img-host")
	full := map[string]any{"id": img1, "repo_tags": []any{"postgres:18"}, "os": "linux", "arch": "amd64", "layers": []any{"sha256:l0"}}
	e.push(h, 0, map[string]any{"docker_images": stOK()}, map[string]any{"images": []any{full}})
	e.push(h, 1, map[string]any{"docker_images": stOK()}, map[string]any{"images": []any{
		map[string]any{"id": img1, "repo_tags": []any{"postgres:18", "postgres:latest"}, "inspect_error": "x"}}})
	rows, err := e.s.Pool.Query(context.Background(), `
		SELECT hi.first_seen_at, hi.removed_at IS NULL, hi.os, hi.variant, hi.repo_tags, ci.image_id IS NOT NULL
		FROM host_images hi LEFT JOIN container_images ci USING (image_id, os, arch, variant)
		WHERE hi.host_id = $1 ORDER BY hi.first_seen_at`, h)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var first time.Time
		var open, joined bool
		var os, variant *string
		var tags []string
		if err := rows.Scan(&first, &open, &os, &variant, &tags, &joined); err != nil {
			t.Fatal(err)
		}
		if os == nil || *os != "linux" || variant == nil || *variant != "" || !joined {
			t.Errorf("range %d: os=%v variant=%v joined=%v (tags %v)", n, os, variant, joined, tags)
		}
		n++
	}
	if n != 2 {
		t.Errorf("ranges = %d, want 2 (re-tag opens a new range)", n)
	}
}

func manager(clusterID string) map[string]any {
	return map[string]any{"state": "active", "node_id": "node-" + clusterID, "cluster_id": clusterID, "role": "manager"}
}

func svc(id string, running int, image string) map[string]any {
	return map[string]any{"id": id, "name": "web_" + id, "image": image, "mode": "replicated", "replicas": 2,
		"running_tasks": running, "desired_tasks": 2,
		"labels": map[string]any{"com.docker.stack.namespace": "web"},
		"ports":  []any{map[string]any{"published": 443, "target": 8443, "proto": "tcp", "publish_mode": "ingress"}}}
}

type svcRange struct {
	Key            string
	First, Removed int
	Running        int
}

func (e *dockerEnv) services(userID, clusterID string) []svcRange {
	e.t.Helper()
	rows, err := e.s.Pool.Query(context.Background(), `
		SELECT row_key, first_seen_at, removed_at, coalesce(running_tasks, -1) FROM swarm_services
		WHERE user_id = $1 AND cluster_id = $2 ORDER BY row_key, first_seen_at`, userID, clusterID)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var out []svcRange
	for rows.Next() {
		var r svcRange
		var first time.Time
		var removed *time.Time
		if err := rows.Scan(&r.Key, &first, &removed, &r.Running); err != nil {
			e.t.Fatal(err)
		}
		r.First, r.Removed = int(first.Sub(e.t0).Minutes()), -1
		if removed != nil {
			r.Removed = int(removed.Sub(e.t0).Minutes())
		}
		out = append(out, r)
	}
	return out
}

func TestDockerIngestSwarm(t *testing.T) {
	e := newDockerEnv(t)
	u := e.user()
	m1, m2, w := e.host(u, "m1"), e.host(u, "m2"), e.host(u, "w")
	ctx := context.Background()
	swarmOK := map[string]any{"docker_engine": stOK(), "swarm_services": stOK()}

	e.push(m1, 0, swarmOK, map[string]any{"engine": map[string]any{"version": "29"}, "swarm": manager("C"),
		"swarm_services": []any{svc("s1", 2, "api:1"), svc("s2", 1, "db:1")}})
	want := []svcRange{{"s1", 0, -1, 2}, {"s2", 0, -1, 1}}
	if got := e.services(u, "C"); !reflect.DeepEqual(got, want) {
		t.Fatalf("after m1: %+v", got)
	}

	// A worker never writes services, even one claiming ok with a list.
	e.push(w, 1, map[string]any{"docker_engine": stOK(), "swarm_services": skipped("not a swarm manager")},
		map[string]any{"engine": map[string]any{"version": "29"}, "swarm": map[string]any{"state": "active", "node_id": "wn", "role": "worker"}})
	var wCluster *string
	if err := e.s.Pool.QueryRow(ctx, `SELECT swarm_cluster_id FROM host_docker WHERE host_id = $1`, w).Scan(&wCluster); err != nil || wCluster != nil {
		t.Errorf("worker cluster id = %v, %v (workers aren't told it)", wCluster, err)
	}
	res := e.push(w, 2, swarmOK, map[string]any{"engine": map[string]any{"version": "29"},
		"swarm":          map[string]any{"state": "active", "node_id": "wn", "cluster_id": "C", "role": "worker"},
		"swarm_services": []any{}})
	if res.SwarmServices != nil {
		t.Errorf("worker push applied services: %+v", res.SwarmServices)
	}

	// Another manager of the cluster: s2 gone (closed), s1's running count
	// changed (in place), s3 new.
	e.push(m2, 3, swarmOK, map[string]any{"engine": map[string]any{"version": "29"}, "swarm": manager("C"),
		"swarm_services": []any{svc("s1", 1, "api:1"), svc("s3", 1, "cache:1")}})
	want = []svcRange{{"s1", 0, -1, 1}, {"s2", 0, 3, 1}, {"s3", 3, -1, 1}}
	if got := e.services(u, "C"); !reflect.DeepEqual(got, want) {
		t.Errorf("after m2: %+v", got)
	}

	// m1's late push (older than m2's) is stale for the cluster.
	res = e.push(m1, 2, swarmOK, map[string]any{"engine": map[string]any{"version": "29"}, "swarm": manager("C"),
		"swarm_services": []any{}})
	if res.SwarmServices == nil || res.SwarmServices.Outcome != store.InventoryStale {
		t.Errorf("late push: %+v", res.SwarmServices)
	}

	// Image update opens a new range.
	e.push(m1, 4, swarmOK, map[string]any{"engine": map[string]any{"version": "29"}, "swarm": manager("C"),
		"swarm_services": []any{svc("s1", 1, "api:2"), svc("s3", 1, "cache:1")}})
	want = []svcRange{{"s1", 0, 4, 1}, {"s1", 4, -1, 1}, {"s2", 0, 3, 1}, {"s3", 3, -1, 1}}
	if got := e.services(u, "C"); !reflect.DeepEqual(got, want) {
		t.Errorf("after update: %+v", got)
	}

	// Locked manager: services skipped, nothing closes, membership kept.
	e.push(m1, 5, map[string]any{"docker_engine": stOK(), "swarm_services": skipped("swarm locked")},
		map[string]any{"engine": map[string]any{"version": "29"}, "swarm": map[string]any{"state": "locked"}})
	if got := e.services(u, "C"); !reflect.DeepEqual(got, want) {
		t.Errorf("after locked push: %+v", got)
	}
	var state, cluster, role string
	if err := e.s.Pool.QueryRow(ctx, `SELECT swarm_state, swarm_cluster_id, swarm_role FROM host_docker WHERE host_id = $1`, m1).
		Scan(&state, &cluster, &role); err != nil || state != "locked" || cluster != "C" || role != "manager" {
		t.Errorf("locked membership: %q %q %q %v", state, cluster, role, err)
	}

	// Another user's manager with the same cluster id gets its own cluster.
	u2 := e.user()
	other := e.host(u2, "other")
	e.push(other, 6, swarmOK, map[string]any{"engine": map[string]any{"version": "29"}, "swarm": manager("C"),
		"swarm_services": []any{}})
	if got := e.services(u, "C"); !reflect.DeepEqual(got, want) {
		t.Errorf("other user's push touched this cluster: %+v", got)
	}
	var clusters int
	if err := e.s.Pool.QueryRow(ctx, `SELECT count(*) FROM swarm_clusters WHERE cluster_id = 'C' AND user_id IN ($1, $2)`, u, u2).
		Scan(&clusters); err != nil || clusters != 2 {
		t.Errorf("clusters = %d, %v", clusters, err)
	}
}
