package reports

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"
)

// ExampleFile is the snapshot fixture, shared with the web app (which
// type-checks it against web/src/lib/report-snapshot.ts). It lives in web/
// because the web image is built from that directory alone.
const ExampleFile = "../../../web/src/lib/report-snapshot.example.json"

// The fixture must decode into Snapshot with no unknown fields and encode
// back to the same JSON: every field it has is in the Go types, and every
// field of the Go types is in it (a field missing from the fixture would
// come back as a zero value and fail the comparison).
func TestExampleRoundTrips(t *testing.T) {
	raw, err := os.ReadFile(ExampleFile)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var s Snapshot
	if err := dec.Decode(&s); err != nil {
		t.Fatalf("decode %s: %v", ExampleFile, err)
	}
	out, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round trip differs:\nfixture: %s\nencoded: %s", compact(t, raw), out)
	}

	if s.SchemaVersion != SchemaVersion || s.RankingVersion != RankingVersion {
		t.Errorf("fixture versions %d/%d, want %d/%d", s.SchemaVersion, s.RankingVersion, SchemaVersion, RankingVersion)
	}
	if s.Changes == nil || len(s.Changes.HostsAdded) == 0 {
		t.Error("fixture should exercise changes with a host added")
	}
	assertNoNilLists(t, s)
}

// assertNoNilLists fails for any nil slice or map reachable from v: they
// would encode as null, and the contract says lists are always [].
func assertNoNilLists(t *testing.T, v any) {
	t.Helper()
	var walk func(rv reflect.Value, path string)
	walk = func(rv reflect.Value, path string) {
		switch rv.Kind() {
		case reflect.Pointer:
			if !rv.IsNil() {
				walk(rv.Elem(), path)
			}
		case reflect.Struct:
			if rv.Type() == reflect.TypeFor[time.Time]() {
				return
			}
			for i := range rv.NumField() {
				walk(rv.Field(i), path+"."+rv.Type().Field(i).Name)
			}
		case reflect.Slice:
			if rv.IsNil() {
				t.Errorf("%s is nil (encodes as null, want [])", path)
			}
			for i := range rv.Len() {
				walk(rv.Index(i), fmt.Sprintf("%s[%d]", path, i))
			}
		case reflect.Map:
			if rv.IsNil() {
				t.Errorf("%s is nil (encodes as null, want {})", path)
			}
			for _, k := range rv.MapKeys() {
				walk(rv.MapIndex(k), fmt.Sprintf("%s[%v]", path, k))
			}
		}
	}
	walk(reflect.ValueOf(v), "Snapshot")
}

func compact(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
