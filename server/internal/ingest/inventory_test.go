package ingest

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/inventory"
)

func decode(t *testing.T, s string) SnapshotPayload {
	t.Helper()
	var p SnapshotPayload
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

const jammy = `"os": {"id": "ubuntu", "version_id": "22.04", "codename": "jammy"}`

func ecosystems(sets []inventory.Set) []string {
	var out []string
	for _, s := range sets {
		out = append(out, s.Ecosystem)
	}
	return out
}

func TestPlanLegacyAgentDefaults(t *testing.T) {
	// Pre-collectors agent: no collectors, no source/ecosystem fields.
	p := decode(t, `{"schema_version": 1, `+jammy+`,
		"packages": [{"name": "libssl3", "version": "3.0.2-0ubuntu1.15", "arch": "amd64"}]}`)
	sets, skipped := planInventory(p)
	if len(sets) != 1 || len(skipped) != 0 {
		t.Fatalf("sets=%v skipped=%v", ecosystems(sets), skipped)
	}
	s := sets[0]
	if s.Ecosystem != "deb" || s.Distro != "ubuntu" || s.Release != "jammy" {
		t.Fatalf("scope = %s/%s/%s", s.Ecosystem, s.Distro, s.Release)
	}
	want := inventory.Item{Name: "libssl3", Version: "3.0.2-0ubuntu1.15", Arch: "amd64",
		Source: "libssl3", SourceVersion: "3.0.2-0ubuntu1.15", SourceInferred: true}
	if s.Items[0] != want {
		t.Fatalf("item = %#v, want %#v", s.Items[0], want)
	}
}

func TestPlanNeverAuthoritative(t *testing.T) {
	cases := map[string]string{
		"legacy, packages missing": `{"schema_version": 1, ` + jammy + `}`,
		"legacy, packages null":    `{"schema_version": 1, ` + jammy + `, "packages": null}`,
		"legacy, packages empty":   `{"schema_version": 1, ` + jammy + `, "packages": []}`,
		"deb collector error, packages null": `{"schema_version": 1, ` + jammy + `,
			"collectors": {"os": {"status": "ok"}, "deb_packages": {"status": "error", "error": "boom"}},
			"packages": null}`,
		"deb collector error, packages present anyway": `{"schema_version": 1, ` + jammy + `,
			"collectors": {"os": {"status": "ok"}, "deb_packages": {"status": "error", "error": "boom"}},
			"packages": [{"name": "a", "version": "1", "arch": "amd64", "ecosystem": "deb"}]}`,
		"deb collector skipped": `{"schema_version": 1, ` + jammy + `,
			"collectors": {"os": {"status": "ok"}, "deb_packages": {"status": "skipped", "reason": "not debian"}},
			"packages": []}`,
		"deb collector missing from map": `{"schema_version": 1, ` + jammy + `,
			"collectors": {"os": {"status": "ok"}},
			"packages": [{"name": "a", "version": "1", "arch": "amd64", "ecosystem": "deb"}]}`,
		"deb ok but packages null": `{"schema_version": 1, ` + jammy + `,
			"collectors": {"os": {"status": "ok"}, "deb_packages": {"status": "ok"}},
			"packages": null}`,
		"deb ok but os collector failed": `{"schema_version": 1, "os": {"id": "", "version_id": "", "codename": ""},
			"collectors": {"os": {"status": "error", "error": "no os-release"}, "deb_packages": {"status": "ok"}},
			"packages": [{"name": "a", "version": "1", "arch": "amd64", "ecosystem": "deb"}]}`,
		"legacy, os id empty": `{"schema_version": 1, "os": {"id": ""},
			"packages": [{"name": "a", "version": "1", "arch": "amd64"}]}`,
		"unknown status value": `{"schema_version": 1, ` + jammy + `,
			"collectors": {"os": {"status": "ok"}, "deb_packages": {"status": "OK"}},
			"packages": [{"name": "a", "version": "1", "arch": "amd64", "ecosystem": "deb"}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			sets, _ := planInventory(decode(t, body))
			if len(sets) != 0 {
				t.Fatalf("got authoritative sets %v; ranges could be closed on missing data", ecosystems(sets))
			}
		})
	}
}

func TestPlanOKAndEmptyIsAuthoritative(t *testing.T) {
	p := decode(t, `{"schema_version": 1, `+jammy+`,
		"collectors": {"os": {"status": "ok"}, "deb_packages": {"status": "ok"}},
		"packages": []}`)
	sets, _ := planInventory(p)
	if len(sets) != 1 || sets[0].Ecosystem != "deb" || len(sets[0].Items) != 0 {
		t.Fatalf("want one empty authoritative deb set, got %#v", sets)
	}
}

func TestPlanPerEcosystemIndependence(t *testing.T) {
	// A future multi-source host: deb ok, rpm failed. Only deb is diffed;
	// "homebrew" (not distro-scoped) is ok and gets an empty distro/release.
	p := decode(t, `{"schema_version": 1, `+jammy+`,
		"collectors": {"os": {"status": "ok"}, "deb_packages": {"status": "ok"},
			"rpm_packages": {"status": "error", "error": "rpmdb locked"},
			"homebrew_packages": {"status": "ok"}},
		"packages": [
			{"name": "a", "version": "1", "arch": "amd64", "source": "a-src", "source_version": "1", "ecosystem": "deb"},
			{"name": "b", "version": "2", "arch": "x86_64", "ecosystem": "rpm"},
			{"name": "jq", "version": "1.7", "arch": "", "ecosystem": "homebrew"}
		]}`)
	sets, skipped := planInventory(p)
	got := ecosystems(sets)
	if len(got) != 2 || got[0] != "deb" || got[1] != "homebrew" {
		t.Fatalf("sets = %v", got)
	}
	if sets[1].Distro != "" || sets[1].Release != "" {
		t.Fatalf("homebrew should not be distro-scoped: %#v", sets[1])
	}
	if sets[0].Items[0].SourceInferred || sets[0].Items[0].Source != "a-src" {
		t.Fatalf("real source lost: %#v", sets[0].Items[0])
	}
	if len(skipped) != 1 || skipped[0].Ecosystem != "rpm" {
		t.Fatalf("skipped = %v", skipped)
	}
}

func TestDefaultPackage(t *testing.T) {
	eco, it := defaultPackage(Package{Name: "libfoo1", Version: "1.2-3+b1", Arch: "amd64", Source: "foo"})
	if eco != "deb" || it.Source != "foo" || it.SourceVersion != "1.2-3+b1" || it.SourceInferred {
		t.Fatalf("Source: foo form: eco=%s %#v", eco, it)
	}
	_, it = defaultPackage(Package{Name: "libfoo1", Version: "1.2-3+b1", Arch: "amd64",
		Source: "foo", SourceVersion: "1.2-3", Ecosystem: "deb"})
	if it.SourceVersion != "1.2-3" {
		t.Fatalf("explicit source version lost: %#v", it)
	}
}

func TestPlanDropsInvalidItems(t *testing.T) {
	p := decode(t, `{"schema_version": 1, `+jammy+`, "packages": [
		{"name": "", "version": "1", "arch": "amd64"},
		{"name": "a", "version": "", "arch": "amd64"},
		{"name": "nul\u0000", "version": "1", "arch": "amd64"},
		{"name": "ok", "version": "1", "arch": "amd64"}]}`)
	sets, _ := planInventory(p)
	if len(sets) != 1 || len(sets[0].Items) != 1 || sets[0].Items[0].Name != "ok" {
		t.Fatalf("got %#v", sets)
	}
}

func TestBuildSnapshotInput(t *testing.T) {
	p := decode(t, `{"schema_version": 1, `+jammy+`,
		"collectors": {"os": {"status": "ok"}, "deb_packages": {"status": "ok"}, "homebrew_packages": {"status": "ok"}},
		"packages": [
			{"name": "a", "version": "1", "arch": "amd64", "ecosystem": "deb"},
			{"name": "jq", "version": "1.7", "arch": "", "ecosystem": "homebrew"}]}`)
	p.SchemaVersion = 7
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

	in := buildSnapshotInput(p, "host", now.Add(time.Hour), now, "192.0.2.1")
	if in.SchemaVersion != 7 {
		t.Fatalf("schema_version not passed through: %d", in.SchemaVersion)
	}
	if !in.InventoryAt.Equal(now) || !in.CollectedAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("future collected_at must clamp only the range boundary: at=%v collected=%v", in.InventoryAt, in.CollectedAt)
	}
	if len(in.Inventory) != 2 || in.CollectorStatus == nil {
		t.Fatalf("inventory=%d collector_status=%s", len(in.Inventory), in.CollectorStatus)
	}

	past := now.Add(-time.Minute)
	if in := buildSnapshotInput(p, "host", past, now, ""); !in.InventoryAt.Equal(past) {
		t.Fatalf("past collected_at must be kept: %v", in.InventoryAt)
	}
	legacy := decode(t, `{"schema_version": 1, `+jammy+`, "packages": [{"name": "a", "version": "1", "arch": "amd64"}]}`)
	if in := buildSnapshotInput(legacy, "host", past, now, ""); in.CollectorStatus != nil {
		t.Fatalf("absent collectors must be stored as NULL, got %s", in.CollectorStatus)
	}
}

func TestKernelRelease(t *testing.T) {
	ok := map[string]CollectorStatus{CollectorKernel: {Status: CollectorStatusOK}}
	failed := map[string]CollectorStatus{CollectorKernel: {Status: "error", Error: "boom"}}
	tests := []struct {
		name string
		p    SnapshotPayload
		want string
	}{
		{"collector ok", SnapshotPayload{OS: OSRelease{Kernel: "6.8.0-45-generic"}, Collectors: ok}, "6.8.0-45-generic"},
		{"trimmed", SnapshotPayload{OS: OSRelease{Kernel: " 6.8.0-45-generic\n"}, Collectors: ok}, "6.8.0-45-generic"},
		{"collector failed", SnapshotPayload{OS: OSRelease{Kernel: "6.8.0-45-generic"}, Collectors: failed}, ""},
		{"collector missing from map (older agent with collectors)", SnapshotPayload{OS: OSRelease{Kernel: "6.8.0-45-generic"},
			Collectors: map[string]CollectorStatus{}}, ""},
		{"legacy payload without collectors", SnapshotPayload{OS: OSRelease{Kernel: "5.15.0-91-generic"}}, "5.15.0-91-generic"},
		{"absent", SnapshotPayload{Collectors: ok}, ""},
		{"garbage", SnapshotPayload{OS: OSRelease{Kernel: "a b"}, Collectors: ok}, ""},
	}
	for _, tt := range tests {
		if got := kernelRelease(tt.p); got != tt.want {
			t.Errorf("%s: kernelRelease = %q, want %q", tt.name, got, tt.want)
		}
	}
	in := buildSnapshotInput(SnapshotPayload{SchemaVersion: 1, OS: OSRelease{ID: "ubuntu", Kernel: "6.8.0-45-generic"},
		Collectors: ok}, "h", time.Now(), time.Now(), "")
	if in.KernelRelease != "6.8.0-45-generic" {
		t.Errorf("SnapshotInput.KernelRelease = %q", in.KernelRelease)
	}
}
