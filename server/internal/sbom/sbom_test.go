package sbom

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/purl"
)

// predicate reads the SBOM out of a testdata in-toto statement (real
// Docker Hub attestations, trimmed to a few packages).
func predicate(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Predicate json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	return st.Predicate
}

func byName(d *Document) map[string]Package {
	out := map[string]Package{}
	for _, p := range d.Packages {
		out[p.PURL.Type+":"+p.PURL.Name] = p
	}
	return out
}

// postgres:17 linux/amd64, Docker Scout SPDX: OS from purl qualifiers,
// source packages from GENERATED_FROM, source-only entries dropped.
func TestParseSPDXDockerScout(t *testing.T) {
	d, err := Parse(FormatSPDX, predicate(t, "postgres17-amd64.spdx.intoto.json"))
	if err != nil {
		t.Fatal(err)
	}
	if d.ToolName != "docker-scout" || d.ToolVersion != "1.18.1" {
		t.Errorf("tool = %q %q", d.ToolName, d.ToolVersion)
	}
	if want := time.Date(2026, 9, 19, 0, 36, 31, 0, time.UTC); !d.Created.Equal(want) {
		t.Errorf("created = %v", d.Created)
	}
	if want := (purl.OSRelease{ID: "debian", VersionID: "13", VersionCodename: "trixie"}); d.OS != want {
		t.Errorf("os = %+v", d.OS)
	}
	pk := byName(d)
	for _, gone := range []string{"deb:glibc", "deb:zlib", "deb:gcc-14", "deb:acl", "deb:postgresql-18"} {
		if _, ok := pk[gone]; ok {
			t.Errorf("source-only entry %s listed", gone)
		}
	}
	for _, kept := range []string{"deb:apt", "deb:util-linux", "deb:postgresql-17"} {
		if _, ok := pk[kept]; !ok {
			t.Errorf("binary %s (also a source) missing", kept)
		}
	}
	checks := []struct{ key, upstream string }{
		{"deb:libc6", "glibc@2.41-12+deb13u4"},
		{"deb:bsdutils", "util-linux@2.41.5-0+deb13u1"},
		{"deb:zlib1g", "zlib@1:1.3.dfsg+really1.3.1-1"},
		{"deb:libpq5", "postgresql-18@18.6-1.pgdg13+2"},
		{"deb:apt", ""},
	}
	for _, c := range checks {
		if got := pk[c.key].PURL.Qualifier("upstream"); got != c.upstream {
			t.Errorf("%s upstream = %q, want %q", c.key, got, c.upstream)
		}
	}
	if got := pk["deb:libc6"].Paths; !slices.Equal(got, []string{"/var/lib/dpkg/status"}) {
		t.Errorf("libc6 paths = %v", got)
	}
	if got := pk["golang:gosu"].Paths; !slices.Equal(got, []string{"/usr/local/bin/gosu"}) {
		t.Errorf("gosu paths = %v", got)
	}

	// Mapped the way the worker does: libc6 interns under trixie with
	// source glibc, like a host's dpkg entry.
	m, err := purl.Map(pk["deb:libc6"].PURL, d.OS, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Distro != "debian" || m.Release != "trixie" || m.Item.Source != "glibc" ||
		m.Item.SourceVersion != "2.41-12+deb13u4" || m.Item.SourceInferred {
		t.Errorf("libc6 mapped = %+v", m)
	}
}

// postgres:17-alpine: apk with os_version=3.24 and origin via GENERATED_FROM.
func TestParseSPDXAlpine(t *testing.T) {
	d, err := Parse(FormatSPDX, predicate(t, "postgres17-alpine-amd64.spdx.intoto.json"))
	if err != nil {
		t.Fatal(err)
	}
	if d.OS.ID != "alpine" || d.OS.VersionID != "3.24" || purl.ReleaseFor(d.OS, nil) != "3.24" {
		t.Errorf("os = %+v", d.OS)
	}
	pk := byName(d)
	if got := pk["apk:alpine-baselayout-data"].PURL.Qualifier("upstream"); got != "alpine-baselayout@3.7.2-r1" {
		t.Errorf("origin = %q", got)
	}
	if _, ok := pk["apk:alpine-baselayout"]; !ok {
		t.Error("alpine-baselayout (a binary and an origin) dropped")
	}
	// openssl is only the origin of libssl3 and libcrypto3: every file it
	// CONTAINS is one of theirs.
	if _, ok := pk["apk:openssl"]; ok {
		t.Error("source-only origin openssl listed")
	}
	for _, bin := range []string{"apk:libssl3", "apk:libcrypto3"} {
		if got := pk[bin].PURL.Qualifier("upstream"); got != "openssl@3.5.8-r0" {
			t.Errorf("%s origin = %q", bin, got)
		}
	}
	if got := pk["apk:musl"].Paths; !slices.Equal(got, []string{"/lib/apk/db/installed"}) {
		t.Errorf("musl paths = %v", got)
	}
}

// Docker Scout splits a nested Go module path into a purl subpath
// (postgres:17-alpine's gosu, 2026-09-29); a real package subpath stays.
func TestParseSPDXGoModuleSubpath(t *testing.T) {
	doc := `{
	 "spdxVersion": "SPDX-2.3",
	 "creationInfo": {"creators": ["Tool: docker-scout-1.18.1"], "created": "2026-09-17T21:31:48Z"},
	 "packages": [
	  {"SPDXID": "a", "name": "github.com/moby/sys/user", "versionInfo": "0.1.0",
	   "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:golang/github.com/moby/sys@0.1.0#user"}]},
	  {"SPDXID": "b", "name": "google.golang.org/genproto", "versionInfo": "0.0.1",
	   "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:golang/google.golang.org/genproto@0.0.1#googleapis/api"}]}
	 ]
	}`
	d, err := Parse(FormatSPDX, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	pk := byName(d)
	if u, ok := pk["golang:user"]; !ok || u.PURL.Namespace != "github.com/moby/sys" || u.PURL.Subpath != "" {
		t.Errorf("moby/sys/user = %+v", pk)
	}
	if u := pk["golang:genproto"].PURL; u.Namespace != "google.golang.org" || u.Subpath != "googleapis/api" {
		t.Errorf("genproto = %+v", u)
	}
	m, err := purl.Map(pk["golang:user"].PURL, d.OS, nil)
	if err != nil || m.Item.Name != "github.com/moby/sys/user" {
		t.Errorf("mapped = %+v, %v", m, err)
	}
}

// Syft-style SPDX: an OPERATING-SYSTEM package, sourceInfo paths.
func TestParseSPDXSyft(t *testing.T) {
	doc := `{
	 "spdxVersion": "SPDX-2.3",
	 "creationInfo": {"creators": ["Organization: Anchore, Inc", "Tool: syft-v1.51.0", "Tool: buildkit-v0.32.2"], "created": "2026-09-02T15:52:55Z"},
	 "packages": [
	  {"SPDXID": "os", "name": "ubuntu", "versionInfo": "24.04", "primaryPackagePurpose": "OPERATING-SYSTEM"},
	  {"SPDXID": "a", "name": "libssl3t64", "versionInfo": "3.0.13-0ubuntu3.5",
	   "sourceInfo": "acquired package info from DPKG DB: /var/lib/dpkg/status, /usr/share/doc/libssl3t64/copyright",
	   "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
	     "referenceLocator": "pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.5?arch=amd64&upstream=openssl&distro=ubuntu-24.04"}]},
	  {"SPDXID": "b", "name": "nopurl", "versionInfo": "1"}
	 ]
	}`
	d, err := Parse(FormatSPDX, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if d.ToolName != "syft" || d.ToolVersion != "v1.51.0" || d.OS.ID != "ubuntu" || d.OS.VersionID != "24.04" || d.Skipped != 1 {
		t.Errorf("doc = %+v", d)
	}
	if len(d.Packages) != 1 || !slices.Equal(d.Packages[0].Paths, []string{"/var/lib/dpkg/status"}) {
		t.Errorf("packages = %+v", d.Packages)
	}
}

func TestParseCycloneDX(t *testing.T) {
	doc := `{
	 "bomFormat": "CycloneDX", "specVersion": "1.6",
	 "metadata": {"timestamp": "2026-09-01T10:00:00Z",
	  "tools": {"components": [{"type": "application", "author": "anchore", "name": "syft", "version": "1.51.0"}]}},
	 "components": [
	  {"type": "operating-system", "name": "debian", "version": "12", "description": "Debian GNU/Linux 12 (bookworm)",
	   "properties": [{"name": "syft:distro:versionCodename", "value": "bookworm"}]},
	  {"type": "library", "name": "libc6", "version": "2.36-9+deb12u10",
	   "purl": "pkg:deb/debian/libc6@2.36-9%2Bdeb12u10?arch=amd64&upstream=glibc&distro=debian-12",
	   "properties": [{"name": "syft:location:0:path", "value": "/var/lib/dpkg/status"}]},
	  {"type": "application", "name": "app", "components": [
	    {"type": "library", "name": "express", "version": "4.21.2", "purl": "pkg:npm/express@4.21.2",
	     "evidence": {"occurrences": [{"location": "/app/node_modules/express/package.json"}]}}]}
	 ]
	}`
	d, err := Parse(FormatCycloneDX, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	want := purl.OSRelease{ID: "debian", VersionID: "12", VersionCodename: "bookworm", PrettyName: "Debian GNU/Linux 12 (bookworm)"}
	if d.OS != want || d.ToolName != "syft" || d.ToolVersion != "1.51.0" || d.Skipped != 1 {
		t.Errorf("doc = %+v", d)
	}
	pk := byName(d)
	if len(pk) != 2 || !slices.Equal(pk["npm:express"].Paths, []string{"/app/node_modules/express/package.json"}) ||
		!slices.Equal(pk["deb:libc6"].Paths, []string{"/var/lib/dpkg/status"}) {
		t.Errorf("packages = %+v", d.Packages)
	}

	// 1.4 tools array.
	d, err = Parse(FormatCycloneDX, []byte(`{"bomFormat": "CycloneDX", "metadata": {"tools": [{"vendor": "aquasecurity", "name": "trivy", "version": "0.60.0"}]}}`))
	if err != nil || d.ToolName != "trivy" || d.ToolVersion != "0.60.0" {
		t.Errorf("1.4 tools: %+v %v", d, err)
	}
}

func TestParseErrors(t *testing.T) {
	for _, c := range []struct{ format, doc string }{
		{FormatSPDX, `{"spdxVersion": "SPDX-3.0"}`},
		{FormatSPDX, `not json`},
		{FormatCycloneDX, `{"bomFormat": "SPDX"}`},
		{"xml", `{}`},
	} {
		if _, err := Parse(c.format, []byte(c.doc)); err == nil {
			t.Errorf("%s %s: no error", c.format, c.doc)
		}
	}
}

func TestSplitTool(t *testing.T) {
	for in, want := range map[string][2]string{
		" docker-scout-1.18.1":   {"docker-scout", "1.18.1"}, //nolint:gocritic // leading space is the case under test
		"syft-v1.51.0":           {"syft", "v1.51.0"},
		"buildkit-0.16.0-tianon": {"buildkit", "0.16.0-tianon"},
		"trivy":                  {"trivy", ""},
	} {
		if n, v := splitTool(in); n != want[0] || v != want[1] {
			t.Errorf("splitTool(%q) = %q %q", in, n, v)
		}
	}
}
