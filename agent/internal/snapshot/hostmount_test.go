package snapshot

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pippinmole/upkeep.sh/agent/internal/collector"
	"github.com/pippinmole/upkeep.sh/agent/internal/target"
)

const kernelRecords = `
Package: linux-image-6.8.0-45-generic
Status: install ok installed
Architecture: amd64
Version: 6.8.0-45.45
`

// nonRecursiveHost lays out what the agent sees with the compose example's
// mounts on a host with a separate /var: /host (the fixture's root
// filesystem) with /run and /var as empty mountpoint directories, and the
// nested directories the collectors read under /host-extra.
func nonRecursiveHost(t *testing.T, extraStatus string) (host, extra string) {
	t.Helper()
	host, extra = t.TempDir(), t.TempDir()
	if err := os.CopyFS(host, os.DirFS("testdata/ubuntu")); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(filepath.Join(extra, "var"), os.DirFS("testdata/ubuntu/var")); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"run", "var"} {
		if err := os.RemoveAll(filepath.Join(host, d)); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(host, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(extra, "run/systemd/system"), 0o755); err != nil {
		t.Fatal(err)
	}
	status := filepath.Join(extra, "var/lib/dpkg/status")
	b, err := os.ReadFile(status)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(status, append(b, (kernelRecords+extraStatus)...), 0o644); err != nil {
		t.Fatal(err)
	}
	return host, extra
}

func TestCollectNonRecursiveMount(t *testing.T) {
	host, extra := nonRecursiveHost(t, `
Package: linux-image-6.11.0-19-generic
Status: install ok installed
Architecture: amd64
Version: 6.11.0-19.19~24.04.1
`)
	snap := testCollector().Collect(context.Background(), target.NewLocalWithExtra(host, extra, "testdata/proc"))
	for _, name := range []string{"deb_packages", collector.CollectorSystemdServices, collector.CollectorLocalUsers,
		collector.CollectorUnattendedUpgrades, collector.CollectorRebootRequired, collector.CollectorHostMount} {
		if st := snap.Collectors[name]; st.Status != collector.StatusOK {
			t.Errorf("%s = %+v, want ok", name, st)
		}
	}
	// The flag file isn't visible (run is empty): derived from the kernels.
	if !snap.RebootRequired || snap.RebootSource != collector.RebootSourceKernel ||
		!reflect.DeepEqual(snap.RebootPackages, []string{"linux-image-6.11.0-19-generic"}) {
		t.Errorf("reboot = %v %v %q", snap.RebootRequired, snap.RebootPackages, snap.RebootSource)
	}
}

func TestCollectNonRecursiveRunningNewest(t *testing.T) {
	host, extra := nonRecursiveHost(t, "")
	snap := testCollector().Collect(context.Background(), target.NewLocalWithExtra(host, extra, "testdata/proc"))
	if st := snap.Collectors[collector.CollectorRebootRequired]; st.Status != collector.StatusOK ||
		snap.RebootRequired || snap.RebootSource != collector.RebootSourceKernel {
		t.Errorf("reboot = %+v %v %q", st, snap.RebootRequired, snap.RebootSource)
	}
}

// The extra binds are missing (e.g. the host mount changed to
// non-recursive by hand on a host with a separate /var): the collectors
// say what isn't visible instead of reporting empty data.
func TestCollectMissingMounts(t *testing.T) {
	host, _ := nonRecursiveHost(t, "")
	snap := testCollector().Collect(context.Background(), target.NewLocalWithExtra(host, "", "testdata/proc"))
	for name, want := range map[string]string{
		"deb_packages":                        "var/lib/dpkg/status not visible under " + host + "; check the agent's mounts",
		collector.CollectorUnattendedUpgrades: "var/lib/apt not visible under " + host,
	} {
		st := snap.Collectors[name]
		if st.Status != collector.StatusError || !strings.Contains(st.Error, want) {
			t.Errorf("%s = %+v, want error containing %q", name, st, want)
		}
	}
	// No dpkg inventory and no /run: unknown, not "no reboot pending".
	if st := snap.Collectors[collector.CollectorRebootRequired]; st.Status != collector.StatusSkipped ||
		!strings.Contains(st.Reason, "pending reboot unknown") {
		t.Errorf("reboot_required = %+v, want skipped (unknown)", st)
	}
}

func TestCollectReportsReachableSockets(t *testing.T) {
	host := t.TempDir()
	if err := os.CopyFS(host, os.DirFS("testdata/ubuntu")); err != nil {
		t.Fatal(err)
	}
	// Not a real socket: a regular file must not count.
	if err := os.WriteFile(filepath.Join(host, "run/docker.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	snap := testCollector().Collect(context.Background(), target.NewLocal(host, "testdata/proc"))
	if st := snap.Collectors[collector.CollectorHostMount]; st.Status != collector.StatusOK {
		t.Errorf("host_mount = %+v", st)
	}
	// Bare metal: skipped.
	if st := testCollector().hostMountStatus(target.NewLocal("/", "/proc")); st.Status != collector.StatusSkipped {
		t.Errorf("bare metal host_mount = %+v", st)
	}
}
