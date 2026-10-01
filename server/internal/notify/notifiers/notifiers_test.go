package notifiers

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/pippinmole/upkeep.sh/server/internal/netguard"
	"github.com/pippinmole/upkeep.sh/server/internal/notify"
)

var update = flag.Bool("update", false, "rewrite the dashboard's notifier schema file")

// schemaFile is the dashboard's copy of the channel type schemas: the web
// app renders channel forms and validates input from it.
const schemaFile = "../../../../web/src/lib/notifier-types.json"

// SchemaJSON is the content of schemaFile.
func SchemaJSON() []byte {
	doc := struct {
		Comment    string        `json:"$comment"`
		EventTypes []string      `json:"eventTypes"`
		Types      []notify.Spec `json:"types"`
	}{
		Comment:    "Generated from server/internal/notify/notifiers: go test ./internal/notify/notifiers -update. Do not edit.",
		EventTypes: notify.EventTypes,
		Types:      Registry(&netguard.Guard{}, nil).Specs(),
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

// The web app's schema file must match the registered notifiers.
func TestSchemaFileIsCurrent(t *testing.T) {
	want := SchemaJSON()
	if *update {
		if err := os.WriteFile(schemaFile, want, 0o644); err != nil { //nolint:gosec // committed file, stays world-readable
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(schemaFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale: run `go test ./internal/notify/notifiers -update`", schemaFile)
	}
}

func TestSpecsAreWellFormed(t *testing.T) {
	for _, s := range Registry(&netguard.Guard{}, nil).Specs() {
		if s.Label == "" || len(s.Fields) == 0 {
			t.Errorf("%s: missing label or fields", s.Type)
		}
		seen := map[string]bool{}
		for _, f := range s.Fields {
			if f.Key == "" || f.Label == "" || seen[f.Key] {
				t.Errorf("%s: bad or duplicate field %+v", s.Type, f)
			}
			seen[f.Key] = true
			if f.Generated && !f.Secret {
				t.Errorf("%s.%s: generated fields must be secret", s.Type, f.Key)
			}
		}
	}
}
