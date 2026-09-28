package ingest

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// labelAllowlistFixture is shared with the agent's tests
// (agent/internal/collector/docker_labels_fixture_test.go): both copies of
// the allowlist must match it.
type labelAllowlistFixture struct {
	ExactKeys []string `json:"exact_keys"`
	Prefixes  []string `json:"prefixes"`
	MaxLabels int      `json:"max_labels"`
}

func TestDockerLabelAllowlistMatchesFixture(t *testing.T) {
	b, err := os.ReadFile("../../../docs/docker-label-allowlist.json")
	if err != nil {
		t.Fatal(err)
	}
	var f labelAllowlistFixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range dockerLabelKeys {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	want := slices.Clone(f.ExactKeys)
	slices.Sort(want)
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("server exact keys differ from docs/docker-label-allowlist.json:\n got %v\nwant %v", keys, want)
	}
	if !reflect.DeepEqual(f.Prefixes, []string{ociLabelPrefix}) || f.MaxLabels != maxDockerLabelsPerItem {
		t.Errorf("prefixes %v / max %d, server has %q / %d", f.Prefixes, f.MaxLabels, ociLabelPrefix, maxDockerLabelsPerItem)
	}
}

func TestDockerLabelsFilter(t *testing.T) {
	in := map[string]string{
		"com.docker.compose.project":                    "myapp",
		"com.docker.compose.mytoken":                    "secret", // Docker-owned prefix, not an allowlisted key
		"traefik.http.middlewares.auth.basicauth.users": "admin:$apr1$hash",
		"org.opencontainers.image.version":              "1.0",
		"org.opencontainers.image.":                     "bare prefix",
		"com.docker.swarm.task.id":                      "t1",
	}
	want := map[string]string{
		"com.docker.compose.project":       "myapp",
		"org.opencontainers.image.version": "1.0",
		"com.docker.swarm.task.id":         "t1",
	}
	if got := dockerLabels(in); !reflect.DeepEqual(got, want) {
		t.Errorf("dockerLabels = %v, want %v", got, want)
	}
	if got := dockerLabels(nil); got == nil || len(got) != 0 {
		t.Errorf("dockerLabels(nil) = %#v, want empty non-nil", got)
	}

	// Cap: the lexically first maxDockerLabelsPerItem allowed keys.
	many := map[string]string{"traefik.enable": "true"}
	for i := 0; i < 100; i++ {
		many[fmt.Sprintf("org.opencontainers.image.k%03d", i)] = "v"
	}
	got := dockerLabels(many)
	if len(got) != maxDockerLabelsPerItem || got["org.opencontainers.image.k000"] == "" || got["org.opencontainers.image.k064"] != "" {
		t.Errorf("cap: %d labels", len(got))
	}
}

// Every labels column (containers, images, swarm services) is filtered
// before hashing, and derived columns come from filtered labels only.
func TestPlanDockerFiltersLabels(t *testing.T) {
	bad := `{"traefik.http.middlewares.a.basicauth.users": "admin:hash", "com.docker.compose.project": "p", "com.docker.stack.namespacex": "x"}`
	p := decode(t, `{"schema_version": 1, "collectors": {"docker_engine": {"status": "ok"}, "docker_containers": {"status": "ok"},
		"docker_images": {"status": "ok"}, "swarm_services": {"status": "ok"}},
		"docker": {"engine": {"version": "1"}, "swarm": {"state": "active", "node_id": "n", "cluster_id": "c", "role": "manager"},
			"containers": [{"id": "c1", "labels": `+bad+`, "privileged": false}],
			"images": [{"id": "i1", "os": "linux", "arch": "amd64", "labels": `+bad+`}],
			"swarm_services": [{"id": "s1", "name": "s", "labels": `+bad+`}]}}`)
	plan := planDocker(p)
	want := map[string]string{"com.docker.compose.project": "p"}
	sets := kinds(plan.sets)
	ctr := sets[KindDockerContainers].Rows[0]
	if !reflect.DeepEqual(ctr.Values[11], want) || ctr.Values[5] != "p" || ctr.Values[7] != nil {
		t.Errorf("container labels %v, compose_project %v, swarm_stack %v", ctr.Values[11], ctr.Values[5], ctr.Values[7])
	}
	if len(plan.images) != 1 || !reflect.DeepEqual(plan.images[0].Labels, want) {
		t.Errorf("image labels = %+v", plan.images)
	}
	if plan.swarm == nil || !reflect.DeepEqual(plan.swarm.Set.Rows[0].Values[6], want) || plan.swarm.Set.Rows[0].Values[5] != nil {
		t.Errorf("swarm labels = %+v", plan.swarm)
	}
	for _, v := range []any{ctr.Values[11], plan.images[0].Labels, plan.swarm.Set.Rows[0].Values[6]} {
		if strings.Contains(fmt.Sprint(v), "hash") {
			t.Errorf("secret label survived: %v", v)
		}
	}
}
