package alerting

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"regexp"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the dashboard's alert property catalog file")

// catalogFile is the dashboard's copy of the catalog: the rule dialog is
// rendered and validated from it.
const catalogFile = "../../../web/src/lib/alert-properties.json"

// vectorsFile holds validation cases both validators must agree on.
const vectorsFile = "../../../web/src/lib/alert-conditions.vectors.json"

// CatalogJSON is the content of catalogFile.
func CatalogJSON() []byte {
	doc := struct {
		Comment    string     `json:"$comment"`
		Properties []Property `json:"properties"`
	}{
		Comment:    "Generated from server/internal/alerting/catalog.go: go test ./internal/alerting -update. Do not edit.",
		Properties: Catalog,
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

func TestCatalogFileIsCurrent(t *testing.T) {
	want := CatalogJSON()
	if *update {
		if err := os.WriteFile(catalogFile, want, 0o644); err != nil { //nolint:gosec // committed file, stays world-readable
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(catalogFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale: run `go test ./internal/alerting -update`", catalogFile)
	}
}

func TestCatalogIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Catalog {
		if p.Key == "" || p.Label == "" || p.Description == "" || len(p.Operators) == 0 || seen[p.Key] {
			t.Errorf("bad or duplicate property %q", p.Key)
		}
		seen[p.Key] = true
		ops := map[string]bool{}
		for _, o := range p.Operators {
			if o.Key == "" || o.Label == "" || ops[o.Key] {
				t.Errorf("%s: bad or duplicate operator %q", p.Key, o.Key)
			}
			ops[o.Key] = true
			v := o.Value
			switch v.Kind {
			case ValueNone:
			case ValueInts, ValueInt:
				if v.Min > v.Max || v.Label == "" {
					t.Errorf("%s.%s: bad range or label", p.Key, o.Key)
				}
			case ValueStrings:
				if v.MaxItems == 0 || v.MaxLength == 0 || v.Label == "" {
					t.Errorf("%s.%s: string lists need limits and a label", p.Key, o.Key)
				}
				if v.Pattern != "" {
					regexp.MustCompile(v.Pattern)
				}
			case ValueEnum:
				if len(v.Choices) == 0 {
					t.Errorf("%s.%s: enum without choices", p.Key, o.Key)
				}
			default:
				t.Errorf("%s.%s: unknown value kind %q", p.Key, o.Key, v.Kind)
			}
		}
		for _, o := range p.Options {
			ok := false
			for _, c := range o.Choices {
				ok = ok || c.Value == o.Default
			}
			if !ok {
				t.Errorf("%s.%s: default %q is not a choice", p.Key, o.Key, o.Default)
			}
		}
	}
	if len(SeverityRanks) != 4 {
		t.Error("severity ranks")
	}
}

type vector struct {
	Name       string          `json:"name"`
	Input      json.RawMessage `json:"input"`
	OK         bool            `json:"ok"`
	Normalized json.RawMessage `json:"normalized"`
	Field      string          `json:"field"`
}

func TestConditionVectors(t *testing.T) {
	raw, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) < 20 {
		t.Fatalf("only %d vectors", len(doc.Vectors))
	}
	for _, v := range doc.Vectors {
		c, err := ParseCondition(v.Input)
		if !v.OK {
			var ce *ConditionError
			if !errors.As(err, &ce) || ce.Field != v.Field {
				t.Errorf("%s: want an error on %q, got %v", v.Name, v.Field, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", v.Name, err)
			continue
		}
		if !SameCondition(c.JSON(), v.Normalized) {
			t.Errorf("%s: normalised to %s, want %s", v.Name, c.JSON(), v.Normalized)
		}
		// Normalising is idempotent.
		again, err := ParseCondition(c.JSON())
		if err != nil || !bytes.Equal(again.JSON(), c.JSON()) {
			t.Errorf("%s: not idempotent: %s -> %s (%v)", v.Name, c.JSON(), again.JSON(), err)
		}
	}
}

// The default rules seeded by migration 0024 must be valid conditions.
func TestDefaultRulesValidate(t *testing.T) {
	sql, err := os.ReadFile("../../migrations/0024_alert_rules.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`'(\{"property".*?\})'`).FindAllSubmatch(sql, -1)
	if len(m) == 0 {
		t.Fatal("no seeded conditions found")
	}
	for _, s := range m {
		c, err := ParseCondition(s[1])
		if err != nil {
			t.Errorf("seeded condition %s: %v", s[1], err)
			continue
		}
		if !SameCondition(c.JSON(), s[1]) {
			t.Errorf("seeded condition %s is not normalised (%s)", s[1], c.JSON())
		}
	}
}

func TestAccessors(t *testing.T) {
	c, err := ParseCondition([]byte(`{"property":"host_not_seen","operator":"for_more_than","value":45}`))
	if err != nil || c.Int() != 45 {
		t.Fatalf("int: %v %v", c, err)
	}
	c, _ = ParseCondition([]byte(`{"property":"vulnerability","operator":"severity_at_least","value":"critical"}`))
	if c.Enum() != "critical" || c.Options["source"] != "any" {
		t.Fatalf("enum: %+v", c)
	}
	c, _ = ParseCondition([]byte(`{"property":"listening_port","operator":"in","value":[3389,22]}`))
	if got := c.Ints(); len(got) != 2 || got[0] != 22 {
		t.Fatalf("ints: %v", got)
	}
	c, _ = ParseCondition([]byte(`{"property":"os","operator":"in","value":["Alpine"]}`))
	if got := c.Strings(); len(got) != 1 || got[0] != "alpine" {
		t.Fatalf("strings: %v", got)
	}
	if _, err := ParseCondition([]byte(`{"property":"os","operator":"in","value":["x"],"extra":1}`)); err == nil {
		t.Fatal("unknown top-level field accepted")
	}
	if _, err := ParseCondition([]byte(`not json`)); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestTitles(t *testing.T) {
	cases := map[string]string{
		PortTitle("tcp", 22, false):                                  "Port 22/tcp is listening",
		PortTitle("udp", 5353, true):                                 "Port 5353/udp is listening (not allowed)",
		PortSubject("tcp", 22):                                       "tcp/22",
		PackageTitle("telnetd", true):                                "Package telnetd is installed",
		PackageTitle("fail2ban", false):                              "Package fail2ban is not installed",
		OSTitle(OSName("ubuntu", "22.04", "linux"), false):           "OS is ubuntu 22.04",
		OSTitle(OSName("", "", "windows"), true):                     "OS windows is not allowed",
		VulnTitle("CVE-2024-3094", "xz-utils", "critical", true, ""): "KEV CVE-2024-3094 in xz-utils",
		VulnTitle("CVE-1", "openssl", "high", false, "nginx:1.25"):   "High CVE-1 in openssl (image nginx:1.25)",
		NotSeenTitle(30):                                             "Not seen for more than 30 minutes",
		NotSeenTitle(120):                                            "Not seen for more than 2 hours",
		NotSeenTitle(1440):                                           "Not seen for more than 1 day",
		NotSeenTitle(1):                                              "Not seen for more than 1 minute",
		CollectorTitle("deb_packages"):                               "Collector deb_packages failed",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}
