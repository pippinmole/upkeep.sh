package detect

import (
	"errors"
	"io/fs"
	"os"
	"reflect"
	"testing"
	"testing/fstest"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name    string
		fsys    fs.FS
		want    OS
		wantErr error
	}{
		{
			name: "ubuntu",
			fsys: os.DirFS("testdata/ubuntu-jammy"),
			want: OS{Family: FamilyLinux, ID: "ubuntu", IDLike: []string{"debian"}, VersionID: "22.04", Codename: "jammy"},
		},
		{
			name: "debian via usr/lib/os-release fallback",
			fsys: os.DirFS("testdata/debian-bookworm"),
			want: OS{Family: FamilyLinux, ID: "debian", VersionID: "12", Codename: "bookworm"},
		},
		{
			name: "derivative with multi-value ID_LIKE",
			fsys: os.DirFS("testdata/mint"),
			want: OS{Family: FamilyLinux, ID: "linuxmint", IDLike: []string{"ubuntu", "debian"}, VersionID: "21.3", Codename: "virginia"},
		},
		{
			name: "non-debian linux",
			fsys: os.DirFS("testdata/alpine"),
			want: OS{Family: FamilyLinux, ID: "alpine", VersionID: "3.20.3"},
		},
		{
			name: "windows",
			fsys: fstest.MapFS{"Windows/System32/kernel32.dll": {}},
			want: OS{Family: FamilyWindows},
		},
		{
			name: "macos",
			fsys: fstest.MapFS{"System/Library/CoreServices/SystemVersion.plist": {}},
			want: OS{Family: FamilyMacOS},
		},
		{
			name:    "empty root (e.g. host not mounted)",
			fsys:    fstest.MapFS{},
			want:    OS{},
			wantErr: ErrUnknownOS,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Detect(tt.fsys)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseOSReleaseQuoting(t *testing.T) {
	fsys := fstest.MapFS{"etc/os-release": {Data: []byte(
		"# comment\nID='debian'\n\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n",
	)}}
	got, err := Detect(fsys)
	if err != nil {
		t.Fatal(err)
	}
	want := OS{Family: FamilyLinux, ID: "debian", VersionID: "12", Codename: "bookworm"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestLike(t *testing.T) {
	tests := []struct {
		os   OS
		ids  []string
		want bool
	}{
		{OS{ID: "debian"}, []string{"debian", "ubuntu"}, true},
		{OS{ID: "ubuntu", IDLike: []string{"debian"}}, []string{"debian"}, true},
		{OS{ID: "linuxmint", IDLike: []string{"ubuntu", "debian"}}, []string{"ubuntu"}, true},
		{OS{ID: "alpine"}, []string{"debian", "ubuntu"}, false},
		{OS{ID: "rhel", IDLike: []string{"fedora"}}, []string{"debian"}, false},
		{OS{}, []string{"debian"}, false},
	}
	for _, tt := range tests {
		if got := tt.os.Like(tt.ids...); got != tt.want {
			t.Errorf("%+v.Like(%v) = %v, want %v", tt.os, tt.ids, got, tt.want)
		}
	}
}

func TestLinuxIdentity(t *testing.T) {
	tests := []struct {
		name    string
		fsys    fs.FS
		want    Identity
		wantErr bool
	}{
		{
			name: "machine-id and hostname",
			fsys: os.DirFS("testdata/ubuntu-jammy"),
			want: Identity{MachineID: "0123456789abcdef0123456789abcdef", Hostname: "web-1"},
		},
		{
			name: "no hostname file is fine",
			fsys: os.DirFS("testdata/debian-bookworm"),
			want: Identity{MachineID: "fedcba9876543210fedcba9876543210"},
		},
		{
			name:    "missing machine-id",
			fsys:    fstest.MapFS{"etc/hostname": {Data: []byte("box\n")}},
			want:    Identity{Hostname: "box"},
			wantErr: true,
		},
		{
			name:    "empty machine-id",
			fsys:    fstest.MapFS{"etc/machine-id": {Data: []byte("\n")}},
			wantErr: true,
		},
		{
			name:    "uninitialized machine-id",
			fsys:    fstest.MapFS{"etc/machine-id": {Data: []byte("uninitialized\n")}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LinuxIdentity(tt.fsys)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}
