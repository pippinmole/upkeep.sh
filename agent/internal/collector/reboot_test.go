package collector

import (
	"errors"
	"io/fs"
	"reflect"
	"testing"
	"testing/fstest"
)

func deb(name, version string) Package {
	return Package{Name: name, Version: version, Ecosystem: "deb"}
}

// Ubuntu 24.04 running the GA kernel, with the HWE kernel installed later.
var ubuntuKernels = []Package{
	deb("linux-image-6.8.0-45-generic", "6.8.0-45.45"),
	deb("linux-image-generic", "6.8.0-45.45"), // meta: ignored
	deb("linux-image-unsigned-6.8.0-45-lowlatency", "6.8.0-45.45.1"),
	deb("openssl", "3.0.13-0ubuntu3"),
}

func TestKernelRebootRequired(t *testing.T) {
	newer := append(append([]Package{}, ubuntuKernels...),
		deb("linux-image-6.11.0-19-generic", "6.11.0-19.19~24.04.1"),
		deb("linux-image-6.8.0-47-lowlatency", "6.8.0-47.47"), // other flavor
	)
	older := append(append([]Package{}, ubuntuKernels...),
		deb("linux-image-6.8.0-40-generic", "6.8.0-40.40"),
	)
	debian := []Package{
		deb("linux-image-6.1.0-18-amd64", "6.1.76-1"),
		deb("linux-image-6.1.0-21-amd64", "6.1.90-1"),
		deb("linux-image-6.1.0-21-cloud-amd64", "6.1.90-1"),
		deb("linux-image-amd64", "6.1.90-1"),
	}
	tests := []struct {
		name    string
		running string
		pkgs    []Package
		want    bool
		wantPkg []string
		wantErr bool
	}{
		{"same kernel only", "6.8.0-45-generic", ubuntuKernels, false, nil, false},
		{"newer HWE kernel installed", "6.8.0-45-generic", newer, true, []string{"linux-image-6.11.0-19-generic"}, false},
		{"only an older kernel installed", "6.8.0-45-generic", older, false, nil, false},
		{"running the newest", "6.11.0-19-generic", newer, false, nil, false},
		{"debian", "6.1.0-18-amd64", debian, true, []string{"linux-image-6.1.0-21-amd64"}, false},
		{"unsigned running kernel", "6.8.0-45-lowlatency", newer, true, []string{"linux-image-6.8.0-47-lowlatency"}, false},
		{"not a dpkg kernel (VM/container)", "6.10.14-linuxkit", ubuntuKernels, false, nil, true},
		{"no inventory", "6.8.0-45-generic", nil, false, nil, true},
		{"no running kernel", "", ubuntuKernels, false, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, pkgs, err := kernelRebootRequired(tt.running, tt.pkgs)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want || !reflect.DeepEqual(pkgs, tt.wantPkg) {
				t.Errorf("= %v %v, want %v %v", got, pkgs, tt.want, tt.wantPkg)
			}
		})
	}
}

func TestKernelFlavour(t *testing.T) {
	for rel, want := range map[string]string{
		"6.8.0-45-generic":     "generic",
		"6.8.0-45-generic-64k": "generic-64k",
		"6.8.0-1012-aws":       "aws",
		"6.1.0-18-cloud-amd64": "cloud-amd64",
		"6.6.31+rpt-rpi-v8":    "rpi-v8",
		"6.10.14":              "",
	} {
		if got := kernelFlavour(rel); got != want {
			t.Errorf("kernelFlavour(%q) = %q, want %q", rel, got, want)
		}
	}
}

func TestCollectRebootRequired(t *testing.T) {
	newer := append(append([]Package{}, ubuntuKernels...), deb("linux-image-6.11.0-19-generic", "6.11.0-19.19~24.04.1"))
	visibleRun := func(files map[string]string) fstest.MapFS {
		m := fstest.MapFS{"run/lock": &fstest.MapFile{Mode: fs.ModeDir | 0o755}} // a real /run is never empty
		for k, v := range files {
			m[k] = &fstest.MapFile{Data: []byte(v)}
		}
		return m
	}
	hiddenRun := fstest.MapFS{"run": &fstest.MapFile{Mode: fs.ModeDir | 0o755}} // empty mountpoint dir

	tests := []struct {
		name    string
		fsys    fstest.MapFS
		visible bool
		running string
		pkgs    []Package
		want    Reboot
		unknown bool
	}{
		{
			name:    "flag file present",
			visible: true, fsys: visibleRun(map[string]string{"run/reboot-required": "", "run/reboot-required.pkgs": "libc6\nlibc6\n"}),
			pkgs: ubuntuKernels, running: "6.8.0-45-generic",
			want: Reboot{Required: true, Packages: []string{"libc6"}, Source: RebootSourceFlagFile},
		},
		{
			name:    "flag file present, plus a newer kernel",
			visible: true, fsys: visibleRun(map[string]string{"run/reboot-required": "", "run/reboot-required.pkgs": "libc6\n"}),
			pkgs: newer, running: "6.8.0-45-generic",
			want: Reboot{Required: true, Packages: []string{"libc6", "linux-image-6.11.0-19-generic"}, Source: RebootSourceFlagFile},
		},
		{
			name:    "flag file absent",
			visible: true, fsys: visibleRun(nil), pkgs: ubuntuKernels, running: "6.8.0-45-generic",
			want: Reboot{Source: RebootSourceFlagFile},
		},
		{
			name:    "flag file absent, newer kernel (Debian without update-notifier)",
			visible: true, fsys: visibleRun(nil), pkgs: newer, running: "6.8.0-45-generic",
			want: Reboot{Required: true, Packages: []string{"linux-image-6.11.0-19-generic"}, Source: RebootSourceKernel},
		},
		{
			name:    "flag file absent, kernel unknown: the flag file decides",
			visible: true, fsys: visibleRun(nil), pkgs: ubuntuKernels, running: "6.10.14-linuxkit",
			want: Reboot{Source: RebootSourceFlagFile},
		},
		{
			name: "run hidden, newer kernel",
			fsys: hiddenRun, pkgs: newer, running: "6.8.0-45-generic",
			want: Reboot{Required: true, Packages: []string{"linux-image-6.11.0-19-generic"}, Source: RebootSourceKernel},
		},
		{
			name: "run hidden, running newest",
			fsys: hiddenRun, pkgs: ubuntuKernels, running: "6.8.0-45-generic",
			want: Reboot{Source: RebootSourceKernel},
		},
		{
			// The root filesystem's /run mountpoint dir can hold stale
			// leftovers; they must not be read as the host's flag file.
			name: "run hidden, stale flag file on the root fs is ignored",
			fsys: visibleRun(map[string]string{"run/reboot-required": ""}), pkgs: ubuntuKernels, running: "6.8.0-45-generic",
			want: Reboot{Source: RebootSourceKernel},
		},
		{
			name: "run hidden, kernel not from dpkg: unknown",
			fsys: hiddenRun, pkgs: ubuntuKernels, running: "6.10.14-linuxkit", unknown: true,
		},
		{
			name: "run hidden, no inventory: unknown",
			fsys: hiddenRun, pkgs: nil, running: "6.8.0-45-generic", unknown: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CollectRebootRequired(tt.fsys, tt.visible, tt.running, tt.pkgs)
			if tt.unknown {
				if !errors.Is(err, ErrRebootUnknown) {
					t.Fatalf("err = %v, want ErrRebootUnknown", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}
