package pkgsource

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/pippinmole/upkeep.sh/agent/internal/collector"
	"github.com/pippinmole/upkeep.sh/agent/internal/detect"
	"github.com/pippinmole/upkeep.sh/agent/internal/target"
)

func TestParseDpkgStatusFixture(t *testing.T) {
	f, err := os.Open("testdata/status")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	got, err := parseDpkgStatus(f)
	if err != nil {
		t.Fatal(err)
	}
	want := []collector.Package{
		// Source absent: source = binary. Its Description continuation line
		// " Version: 9.9" must not overwrite the real Version.
		{Name: "openssl", Version: "3.0.2-0ubuntu1.15", Arch: "amd64", Source: "openssl", SourceVersion: "3.0.2-0ubuntu1.15"},
		// "Source: openssl": source version = binary version.
		{Name: "libssl3", Version: "3.0.2-0ubuntu1.15", Arch: "amd64", Source: "openssl", SourceVersion: "3.0.2-0ubuntu1.15"},
		// "Source: foo (1.2-3)": explicit source version (binNMU); "hold"
		// is a want state, still installed.
		{Name: "libfoo1", Version: "1.2-3+b1", Arch: "arm64", Source: "foo", SourceVersion: "1.2-3"},
		// half-installed, not-installed, config-files, unpacked: excluded.
		// triggers-pending: files are on disk, only a trigger is
		// outstanding, so included.
		{Name: "man-db", Version: "2.10.2-1", Arch: "amd64", Source: "man-db", SourceVersion: "2.10.2-1"},
		// half-configured: excluded.
		// Last record, no trailing newline at all: still included.
		{Name: "tzdata", Version: "2024a-0ubuntu0.22.04", Arch: "all", Source: "tzdata", SourceVersion: "2024a-0ubuntu0.22.04"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got:\n%+v\nwant:\n%+v", got, want)
	}
}

func TestParseDpkgStatusRecords(t *testing.T) {
	tests := []struct {
		name   string
		record string
		want   []collector.Package
	}{
		{
			name:   "installed, no Source",
			record: "Package: a\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n",
			want:   []collector.Package{{Name: "a", Version: "1.0", Arch: "amd64", Source: "a", SourceVersion: "1.0"}},
		},
		{
			name:   "Source name only",
			record: "Package: a\nStatus: install ok installed\nArchitecture: amd64\nSource: src\nVersion: 1.0\n",
			want:   []collector.Package{{Name: "a", Version: "1.0", Arch: "amd64", Source: "src", SourceVersion: "1.0"}},
		},
		{
			name:   "Source with version",
			record: "Package: a\nStatus: install ok installed\nArchitecture: amd64\nSource: src (1:0.9-2)\nVersion: 1:0.9-2+b3\n",
			want:   []collector.Package{{Name: "a", Version: "1:0.9-2+b3", Arch: "amd64", Source: "src", SourceVersion: "1:0.9-2"}},
		},
		{
			name:   "Source before Version in record order",
			record: "Package: a\nSource: src (2.0)\nStatus: install ok installed\nVersion: 2.0+b1\nArchitecture: all\n",
			want:   []collector.Package{{Name: "a", Version: "2.0+b1", Arch: "all", Source: "src", SourceVersion: "2.0"}},
		},
		{
			name:   "malformed Source version falls back to binary version",
			record: "Package: a\nStatus: install ok installed\nArchitecture: amd64\nSource: src (\nVersion: 1.0\n",
			want:   []collector.Package{{Name: "a", Version: "1.0", Arch: "amd64", Source: "src", SourceVersion: "1.0"}},
		},
		{
			name:   "triggers-pending",
			record: "Package: a\nStatus: install ok triggers-pending\nArchitecture: amd64\nVersion: 1.0\n",
			want:   []collector.Package{{Name: "a", Version: "1.0", Arch: "amd64", Source: "a", SourceVersion: "1.0"}},
		},
		{
			name:   "triggers-awaited",
			record: "Package: a\nStatus: install ok triggers-awaited\nArchitecture: amd64\nVersion: 1.0\n",
			want:   []collector.Package{{Name: "a", Version: "1.0", Arch: "amd64", Source: "a", SourceVersion: "1.0"}},
		},
		{
			name:   "triggers-pending under hold",
			record: "Package: a\nStatus: hold ok triggers-pending\nArchitecture: amd64\nVersion: 1.0\n",
			want:   []collector.Package{{Name: "a", Version: "1.0", Arch: "amd64", Source: "a", SourceVersion: "1.0"}},
		},
		{name: "unpacked", record: "Package: a\nStatus: install ok unpacked\nVersion: 1.0\n"},
		{name: "half-installed", record: "Package: a\nStatus: install reinstreq half-installed\nVersion: 1.0\n"},
		{name: "not-installed", record: "Package: a\nStatus: purge ok not-installed\n"},
		{name: "config-files", record: "Package: a\nStatus: deinstall ok config-files\nVersion: 1.0\n"},
		{name: "half-configured", record: "Package: a\nStatus: install ok half-configured\nVersion: 1.0\n"},
		{name: "no Status", record: "Package: a\nVersion: 1.0\n"},
		{name: "empty input", record: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDpkgStatus(strings.NewReader(tt.record))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseDpkgStatusBlankLineVariants(t *testing.T) {
	// Records separated by a whitespace-only line, and the last one
	// terminated by a single newline but no blank line.
	in := "Package: a\nStatus: install ok installed\nVersion: 1\n \nPackage: b\nStatus: install ok installed\nVersion: 2\n"
	got, err := parseDpkgStatus(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "a" || got[1].Name != "b" {
		t.Errorf("got %+v, want packages a and b", got)
	}
}

func TestDpkgApplies(t *testing.T) {
	tests := []struct {
		name string
		os   detect.OS
		want bool
	}{
		{"ubuntu", detect.OS{Family: detect.FamilyLinux, ID: "ubuntu", IDLike: []string{"debian"}}, true},
		{"debian", detect.OS{Family: detect.FamilyLinux, ID: "debian"}, true},
		{"mint", detect.OS{Family: detect.FamilyLinux, ID: "linuxmint", IDLike: []string{"ubuntu", "debian"}}, true},
		{"alpine", detect.OS{Family: detect.FamilyLinux, ID: "alpine"}, false},
		{"windows", detect.OS{Family: detect.FamilyWindows}, false},
		{"macos", detect.OS{Family: detect.FamilyMacOS}, false},
		{"undetected", detect.OS{}, false},
		// Family gates it: a debian ID on a non-Linux family can't happen
		// from Detect, but applicability must not rely on that.
		{"debian id without linux family", detect.OS{ID: "debian"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (Dpkg{}).Applies(tt.os); got != tt.want {
				t.Errorf("Applies = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDpkgCollectFromHostRoot(t *testing.T) {
	got, err := Dpkg{}.Collect(context.Background(), target.NewLocal("testdata/ubuntu", ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Errorf("got %d packages, want 4", len(got))
	}

	_, err = Dpkg{}.Collect(context.Background(), target.NewLocal("testdata/debian-no-dpkg", ""))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing dpkg database: err = %v, want fs.ErrNotExist", err)
	}
}
