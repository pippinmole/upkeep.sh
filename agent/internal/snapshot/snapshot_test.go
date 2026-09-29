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
		collector.CollectorOS:                 collector.StatusOK,
		collector.CollectorKernel:             collector.StatusOK,
		collector.CollectorHostIdentity:       collector.StatusOK,
		"deb_packages":                        collector.StatusOK,
		collector.CollectorTCPListeners:       collector.StatusOK,
		collector.CollectorUDPListeners:       collector.StatusOK,
		collector.CollectorRebootRequired:     collector.StatusOK,
		collector.CollectorPublicIP:           collector.StatusOK,
		collector.CollectorUptime:             collector.StatusOK,
		collector.CollectorArch:               collector.StatusOK,
		collector.CollectorSystemdServices:    collector.StatusOK,
		collector.CollectorLocalUsers:         collector.StatusOK,
		collector.CollectorDeletedLibs:        collector.StatusOK,
		collector.CollectorUnattendedUpgrades: collector.StatusOK,
		// testCollector has no Docker opener.
		collector.CollectorDockerEngine:     collector.StatusSkipped,
		collector.CollectorDockerContainers: collector.StatusSkipped,
		collector.CollectorDockerImages:     collector.StatusSkipped,
		collector.CollectorDockerNetworks:   collector.StatusSkipped,
		collector.CollectorSwarmServices:    collector.StatusSkipped,
		collector.CollectorHostMount:        collector.StatusOK,
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
	if want := (collector.OSRelease{ID: "ubuntu", VersionID: "22.04", Codename: "jammy", Kernel: "6.8.0-45-generic", Arch: "amd64"}); snap.OS != want {
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
	if len(snap.ListeningSockets) != 3 || snap.ListeningSockets[2].Proto != "udp" {
		t.Errorf("got %d listening sockets, want 2 TCP LISTEN + 1 UDP: %+v", len(snap.ListeningSockets), snap.ListeningSockets)
	}
	if snap.UptimeSeconds == nil || *snap.UptimeSeconds != 350735 {
		t.Errorf("uptime = %v", snap.UptimeSeconds)
	}
	if len(snap.Services) != 2 || snap.Services[1].Name != "ssh.service" ||
		snap.Services[1].StartMode != "auto" || snap.Services[1].State != "running" ||
		snap.Services[0].StartMode != "disabled" || snap.Services[0].State != "stopped" {
		t.Errorf("services = %+v", snap.Services)
	}
	if len(snap.Users) != 3 || snap.Users[2].Name != "ubuntu" || !snap.Users[2].Admin {
		t.Errorf("users = %+v", snap.Users)
	}
	if snap.Facts == nil || snap.Facts.NeedsRestart == nil || snap.Facts.UnattendedUpgrades == nil {
		t.Fatalf("facts = %+v", snap.Facts)
	}
	if nr := snap.Facts.NeedsRestart.Processes; len(nr) != 1 || nr[0].Unit != "ssh.service" ||
		!reflect.DeepEqual(nr[0].Libraries, []string{"/usr/lib/x86_64-linux-gnu/libssl.so.3"}) {
		t.Errorf("needs_restart = %+v", nr)
	}
	// Configured on, but the unattended-upgrades package isn't in the fixture inventory.
	if uu := snap.Facts.UnattendedUpgrades; uu.UnattendedUpgrade != "1" || uu.Enabled ||
		uu.PackageInstalled == nil || *uu.PackageInstalled {
		t.Errorf("unattended_upgrades = %+v", uu)
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
	for _, name := range []string{collector.CollectorUptime, collector.CollectorUDPListeners, collector.CollectorDeletedLibs} {
		if st := snap.Collectors[name]; st.Status != collector.StatusSkipped {
			t.Errorf("%s without procfs = %+v, want skipped", name, st)
		}
	}
	// No dpkg inventory and no procfs: arch is unknown, reported as a failure.
	if st := snap.Collectors[collector.CollectorArch]; st.Status != collector.StatusError || snap.OS.Arch != "" {
		t.Errorf("arch = %+v (%q), want error", st, snap.OS.Arch)
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
				collector.CollectorTCPListeners, collector.CollectorUDPListeners, collector.CollectorRebootRequired,
				collector.CollectorUptime, collector.CollectorArch, collector.CollectorSystemdServices,
				collector.CollectorLocalUsers, collector.CollectorDeletedLibs, collector.CollectorUnattendedUpgrades,
				collector.CollectorDockerEngine, collector.CollectorDockerContainers, collector.CollectorDockerImages,
				collector.CollectorDockerNetworks, collector.CollectorSwarmServices} {
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

// The agent block is sent when configured and omitted otherwise, so the
// server can tell an older agent from one reporting its build.
func TestCollectAgentBlock(t *testing.T) {
	tgt := target.NewLocal("testdata/ubuntu", "testdata/proc")
	c := testCollector()
	b, _ := json.Marshal(c.Collect(context.Background(), tgt))
	if strings.Contains(string(b), `"agent"`) {
		t.Errorf("agent block sent without Collector.Agent: %s", b)
	}
	c.Agent = &collector.Agent{Version: "1.2.3", Platform: "linux/amd64", IntervalSeconds: 900}
	b, _ = json.Marshal(c.Collect(context.Background(), tgt))
	if !strings.Contains(string(b), `"agent":{"version":"1.2.3","platform":"linux/amd64","interval_seconds":900}`) {
		t.Errorf("agent block missing or wrong: %s", b)
	}
}
