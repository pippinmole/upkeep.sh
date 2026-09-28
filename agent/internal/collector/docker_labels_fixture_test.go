package collector

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"
)

// The server re-applies this allowlist on ingest (server/internal/ingest/
// labels.go). Both copies are checked against one shared fixture so they
// can't drift: change all three together.
func TestDockerLabelAllowlistMatchesFixture(t *testing.T) {
	b, err := os.ReadFile("../../../docs/docker-label-allowlist.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		ExactKeys []string `json:"exact_keys"`
		Prefixes  []string `json:"prefixes"`
		MaxLabels int      `json:"max_labels"`
	}
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
		t.Errorf("agent exact keys differ from docs/docker-label-allowlist.json:\n got %v\nwant %v", keys, want)
	}
	if !reflect.DeepEqual(f.Prefixes, []string{ociLabelPrefix}) || f.MaxLabels != MaxDockerLabels {
		t.Errorf("prefixes %v / max %d, agent has %q / %d", f.Prefixes, f.MaxLabels, ociLabelPrefix, MaxDockerLabels)
	}
}
