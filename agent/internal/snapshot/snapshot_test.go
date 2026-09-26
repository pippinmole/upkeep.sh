package snapshot

import (
	"context"
	"encoding/json"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/pippinmole/upkeep.sh/agent/internal/collector"
	"github.com/pippinmole/upkeep.sh/agent/internal/collector/pkgsource"
	"github.com/pippinmole/upkeep.sh/agent/internal/target"
)

func testCollector() *Collector {
	return &Collector{
		Sources:   pkgsource.Default(),
		PublicIPs: func(context.Context) (string, string) { return "203.0.113.7", "" },
		Now:       func() time.Time { return time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC) },
	}
}

func statuses(snap collector.Snapshot) map[string]string {
	out := map[string]string{}
	for k, v := range snap.Collectors {
		out[k] = v.Status
	}
	return out
}

func TestCollectUbuntu(t *testing.T) {
	snap := testCollector().Collect(context.Background(), target.NewLocal("testdata/ubuntu", "testdata/proc"))

	wantStatus := map[string]string{
		collector.CollectorOS:             collector.StatusOK,
		collector.CollectorKernel:         collector.StatusOK,
		collector.CollectorHostIdentity:   collector.StatusOK,
		"deb_packages":                    collector.StatusOK,
		collector.CollectorTCPListeners:   collector.StatusOK,
		collector.CollectorRebootRequired: collector.StatusOK,
		collector.CollectorPublicIP:       collector.StatusOK,
	}
	if got := statuses(snap); !reflect.DeepEqual(got, wantStatus) {
		t.Errorf("collectors = %v, want %v (full: %+v)", got, wantStatus, snap.Collectors)
	}

	wantHost := collector.Host{
		Ref: "local", OSFamily: "linux", Hostname: "web-1",
		Identity: collector.HostIdentity{MachineID: "0123456789abcdef0123456789abcdef"},
	}
	if snap.Host != wantHost {
		t.Errorf("host = %+v, want %+v", snap.Host, wantHost)
	}
	if want := (collector.OSRelease{ID: "ubuntu", VersionID: "22.04", Codename: "jammy", Kernel: "6.8.0-45-generic"}); snap.OS != want {
		t.Errorf("os = %+v, want %+v", snap.OS, want)
	}
	if snap.SchemaVersion != 1 || snap.CollectedAt != "2026-09-26T12:00:00Z" {
		t.Errorf("schema_version/collected_at = %d/%s", snap.SchemaVersion, snap.CollectedAt)
	}
	if len(snap.Packages) != 4 {
		t.Fatalf("got %d packages, want 4", len(snap.Packages))
	}
	for _, p := range snap.Packages {
		if p.Ecosystem != "deb" || p.Source == "" || p.SourceVersion == "" {
			t.Errorf("package missing ecosystem/source: %+v", p)
		}
	}
	if len(snap.ListeningSockets) != 2 {
		t.Errorf("got %d listening sockets, want 2 (only LISTEN rows): %+v", len(snap.ListeningSockets), snap.ListeningSockets)
	}
	if !snap.RebootRequired || !reflect.DeepEqual(snap.RebootPackages, []string{"linux-image-6.8.0-45-generic", "libc6"}) {
		t.Errorf("reboot = %v %v", snap.RebootRequired, snap.RebootPackages)
	}
	if snap.PublicIPv4 != "203.0.113.7" {
		t.Errorf("public_ipv4 = %q", snap.PublicIPv4)
	}
}

// A failing package source must not abort the snapshot: everything else is
// still collected, the failure is reported, and packages is null (unknown)
// rather than [] (known empty), so the server never reads it as "all
// packages removed".
func TestCollectPackageSourceFailure(t *testing.T) {
	snap := testCollector().Collect(context.Background(), target.NewLocal("testdata/debian-broken", ""))

	deb := snap.Collectors["deb_packages"]
	if deb.Status != collector.StatusError || !strings.Contains(deb.Error, "var/lib/dpkg/status") {
		t.Errorf("deb_packages = %+v, want error mentioning the dpkg database", deb)
	}
	if snap.Packages != nil {
		t.Errorf("packages = %+v, want nil", snap.Packages)
	}
	if st := snap.Collectors[collector.CollectorOS].Status; st != collector.StatusOK {
		t.Errorf("os status = %s, want ok", st)
	}
	if snap.OS.ID != "debian" || snap.Host.Hostname != "deb-host" {
		t.Errorf("rest of snapshot not collected: os=%+v host=%+v", snap.OS, snap.Host)
	}
	if st := snap.Collectors[collector.CollectorTCPListeners]; st.Status != collector.StatusSkipped {
		t.Errorf("tcp_listeners without procfs = %+v, want skipped", st)
	}
	if st := snap.Collectors[collector.CollectorKernel]; st.Status != collector.StatusSkipped || snap.OS.Kernel != "" {
		t.Errorf("kernel without procfs = %+v (%q), want skipped", st, snap.OS.Kernel)
	}

	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"packages":null`) {
		t.Errorf("payload should carry packages:null, got %s", b)
	}
}

func TestCollectNonLinuxAndUndetected(t *testing.T) {
	tests := []struct {
		name       string
		fsys       fs.FS
		wantFamily string
		wantOS     string
	}{
		{"windows", fstest.MapFS{"Windows/System32/kernel32.dll": {}}, "windows", collector.StatusOK},
		{"undetected", fstest.MapFS{}, "", collector.StatusError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snap := testCollector().Collect(context.Background(), fsTarget{tt.fsys})
			if snap.Host.OSFamily != tt.wantFamily {
				t.Errorf("os_family = %q, want %q", snap.Host.OSFamily, tt.wantFamily)
			}
			if got := snap.Collectors[collector.CollectorOS].Status; got != tt.wantOS {
				t.Errorf("os status = %s, want %s", got, tt.wantOS)
			}
			// No Linux collector, and no dpkg, may run on a non-Linux host.
			for _, name := range []string{"deb_packages", collector.CollectorHostIdentity, collector.CollectorKernel,
				collector.CollectorTCPListeners, collector.CollectorRebootRequired} {
				if st := snap.Collectors[name]; st.Status != collector.StatusSkipped {
					t.Errorf("%s = %+v, want skipped", name, st)
				}
			}
			if snap.Packages != nil {
				t.Errorf("packages = %+v, want nil", snap.Packages)
			}
		})
	}
}

// fsTarget is a local-mode target over an in-memory filesystem, with no
// procfs.
type fsTarget struct{ fsys fs.FS }

func (f fsTarget) Ref() string       { return target.LocalRef }
func (f fsTarget) Mode() target.Mode { return target.ModeLocal }
func (f fsTarget) FS() fs.FS         { return f.fsys }
