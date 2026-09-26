package matcher

import "testing"

func TestKernelSource(t *testing.T) {
	tests := []struct {
		distro, in, want string
		wrapped          bool
	}{
		{"ubuntu", "linux-signed", "linux", true},
		{"ubuntu", "linux-signed-hwe-6.8", "linux-hwe-6.8", true},
		{"ubuntu", "linux-signed-aws", "linux-aws", true},
		{"ubuntu", "linux-meta", "linux", true},
		{"ubuntu", "linux-meta-hwe-6.8", "linux-hwe-6.8", true},
		{"ubuntu", "linux-meta-oem-6.8", "linux-oem-6.8", true},
		{"ubuntu", "linux-restricted-modules-hwe-6.8", "linux-hwe-6.8", true},
		{"ubuntu", "linux", "linux", false},
		{"ubuntu", "linux-aws", "linux-aws", false},
		{"ubuntu", "linux-signedfoo", "linux-signedfoo", false}, // not a wrapper
		{"debian", "linux-signed-amd64", "linux", true},
		{"debian", "linux-signed-arm64", "linux", true},
		{"debian", "linux-signed-6.12-amd64", "linux-6.12", true},
		{"debian", "linux", "linux", false},
		{"debian", "openssl", "openssl", false},
	}
	for _, tt := range tests {
		got, w := KernelSource(tt.distro, tt.in)
		if got != tt.want || w != tt.wrapped {
			t.Errorf("KernelSource(%s, %s) = %s, %v; want %s, %v", tt.distro, tt.in, got, w, tt.want, tt.wrapped)
		}
	}
}

func TestIsKernelSource(t *testing.T) {
	for src, want := range map[string]bool{
		"linux": true, "linux-aws": true, "linux-hwe-6.8": true, "linux-lowlatency-hwe-6.8": true,
		"linux-6.12": true, "linux-oem-6.8": true,
		"linux-firmware": false, "linux-atm": false, "linux-base": false, "linux-ftpd": false,
		"linux-entra-sso": false, "linuxptp": false, "linuxcnc": false, "openssl": false,
		"linux-image-5.15.0-91-generic": false, "linux-libc-dev": false,
	} {
		if got := IsKernelSource(src); got != want {
			t.Errorf("IsKernelSource(%s) = %v, want %v", src, got, want)
		}
	}
}

func TestKernelRelease(t *testing.T) {
	for name, want := range map[string]string{
		"linux-image-5.15.0-91-generic":              "5.15.0-91-generic",
		"linux-image-unsigned-6.8.0-45-generic":      "6.8.0-45-generic",
		"linux-modules-6.8.0-45-generic":             "6.8.0-45-generic",
		"linux-modules-extra-5.15.0-91-generic":      "5.15.0-91-generic",
		"linux-image-6.1.0-18-amd64":                 "6.1.0-18-amd64",
		"linux-image-6.1.0-18-amd64-unsigned":        "6.1.0-18-amd64",
		"linux-image-6.12.48+deb13-amd64":            "6.12.48+deb13-amd64",
		"linux-image-6.1.0-18-cloud-amd64":           "6.1.0-18-cloud-amd64",
		"linux-image-6.1.0-18-amd64-dbg":             "",
		"linux-image-generic":                        "",
		"linux-image-amd64":                          "",
		"linux-headers-5.15.0-91-generic":            "",
		"linux-headers-5.15.0-91":                    "",
		"linux-tools-5.15.0-91-generic":              "",
		"linux-modules-nvidia-535-5.15.0-91-generic": "",
		"linux-libc-dev":                             "",
	} {
		got, ok := KernelRelease(name)
		if got != want || ok != (want != "") {
			t.Errorf("KernelRelease(%s) = %q, %v; want %q", name, got, ok, want)
		}
	}
}

func TestResolve(t *testing.T) {
	tests := []struct {
		name string
		b    Binary
		want Target
	}{
		{"ordinary package", Binary{Ecosystem: "deb", Distro: "ubuntu", Name: "libssl3", Version: "3.0.2-0ubuntu1.15",
			Source: "openssl", SourceVersion: "3.0.2-0ubuntu1.15"},
			Target{Source: "openssl", Version: "3.0.2-0ubuntu1.15"}},
		{"binNMU source version", Binary{Ecosystem: "deb", Distro: "debian", Name: "libfoo1", Version: "1.0-1+b1",
			Source: "foo", SourceVersion: "1.0-1"},
			Target{Source: "foo", Version: "1.0-1"}},
		{"ubuntu signed image", Binary{Ecosystem: "deb", Distro: "ubuntu", Name: "linux-image-5.15.0-91-generic",
			Version: "5.15.0-91.101", Source: "linux-signed", SourceVersion: "5.15.0-91.101"},
			Target{Source: "linux", Version: "5.15.0-91.101", KernelRelease: "5.15.0-91-generic"}},
		{"ubuntu hwe signed image", Binary{Ecosystem: "deb", Distro: "ubuntu", Name: "linux-image-6.8.0-45-generic",
			Version: "6.8.0-45.45~22.04.1", Source: "linux-signed-hwe-6.8", SourceVersion: "6.8.0-45.45~22.04.1"},
			Target{Source: "linux-hwe-6.8", Version: "6.8.0-45.45~22.04.1", KernelRelease: "6.8.0-45-generic"}},
		{"ubuntu modules (direct source)", Binary{Ecosystem: "deb", Distro: "ubuntu", Name: "linux-modules-5.15.0-91-generic",
			Version: "5.15.0-91.101", Source: "linux", SourceVersion: "5.15.0-91.101"},
			Target{Source: "linux", Version: "5.15.0-91.101", KernelRelease: "5.15.0-91-generic"}},
		{"ubuntu aws image", Binary{Ecosystem: "deb", Distro: "ubuntu", Name: "linux-image-6.8.0-1015-aws",
			Version: "6.8.0-1015.16~22.04.1", Source: "linux-signed-aws-6.8", SourceVersion: "6.8.0-1015.16~22.04.1"},
			Target{Source: "linux-aws-6.8", Version: "6.8.0-1015.16~22.04.1", KernelRelease: "6.8.0-1015-aws"}},
		{"ubuntu meta is not matched", Binary{Ecosystem: "deb", Distro: "ubuntu", Name: "linux-image-generic",
			Version: "5.15.0.91.88", Source: "linux-meta", SourceVersion: "5.15.0.91.88"}, Target{}},
		{"linux-libc-dev is not matched", Binary{Ecosystem: "deb", Distro: "ubuntu", Name: "linux-libc-dev",
			Version: "5.15.0-91.101", Source: "linux", SourceVersion: "5.15.0-91.101"}, Target{}},
		{"headers not matched", Binary{Ecosystem: "deb", Distro: "ubuntu", Name: "linux-headers-5.15.0-91-generic",
			Version: "5.15.0-91.101", Source: "linux", SourceVersion: "5.15.0-91.101"}, Target{}},
		// Debian: signed source version is "6.1.76+1"; the binary version is
		// the kernel source version the advisories compare against.
		{"debian signed image", Binary{Ecosystem: "deb", Distro: "debian", Name: "linux-image-6.1.0-18-amd64",
			Version: "6.1.76-1", Source: "linux-signed-amd64", SourceVersion: "6.1.76+1"},
			Target{Source: "linux", Version: "6.1.76-1", KernelRelease: "6.1.0-18-amd64"}},
		{"debian meta not matched", Binary{Ecosystem: "deb", Distro: "debian", Name: "linux-image-amd64",
			Version: "6.1.76-1", Source: "linux-signed-amd64", SourceVersion: "6.1.76+1"}, Target{}},
		{"debian bpftool (from linux) not matched", Binary{Ecosystem: "deb", Distro: "debian", Name: "bpftool",
			Version: "7.1.0+6.1.76-1", Source: "linux", SourceVersion: "6.1.76-1"}, Target{}},
		{"linux-firmware is a normal package", Binary{Ecosystem: "deb", Distro: "ubuntu", Name: "linux-firmware",
			Version: "20220329.git681281e4-0ubuntu3.36", Source: "linux-firmware", SourceVersion: "20220329.git681281e4-0ubuntu3.36"},
			Target{Source: "linux-firmware", Version: "20220329.git681281e4-0ubuntu3.36"}},
		{"inferred ordinary", Binary{Ecosystem: "deb", Distro: "ubuntu", Name: "bash", Version: "5.1-6ubuntu1",
			Source: "bash", SourceVersion: "5.1-6ubuntu1", SourceInferred: true},
			Target{Source: "bash", Version: "5.1-6ubuntu1"}},
		{"inferred kernel not matched", Binary{Ecosystem: "deb", Distro: "ubuntu", Name: "linux-image-5.15.0-91-generic",
			Version: "5.15.0-91.101", Source: "linux-image-5.15.0-91-generic", SourceVersion: "5.15.0-91.101", SourceInferred: true},
			Target{}},
		{"non-deb", Binary{Ecosystem: "homebrew", Name: "openssl", Version: "3.0", Source: "openssl", SourceVersion: "3.0"}, Target{}},
	}
	for _, tt := range tests {
		if got := Resolve(tt.b); got != tt.want {
			t.Errorf("%s: Resolve = %+v, want %+v", tt.name, got, tt.want)
		}
	}
}

func TestRaisesFinding(t *testing.T) {
	tests := []struct {
		name, kernel, running string
		raise, unknown        bool
	}{
		{"not a kernel", "", "5.15.0-91-generic", true, false},
		{"not a kernel, running unknown", "", "", true, false},
		{"running kernel", "5.15.0-91-generic", "5.15.0-91-generic", true, false},
		{"installed, not running", "5.15.0-88-generic", "5.15.0-91-generic", false, false},
		{"other flavour, same ABI", "5.15.0-91-lowlatency", "5.15.0-91-generic", false, false},
		{"running unknown: all kernels raise, flagged", "5.15.0-88-generic", "", true, true},
	}
	for _, tt := range tests {
		raise, unknown := RaisesFinding(tt.kernel, tt.running)
		if raise != tt.raise || unknown != tt.unknown {
			t.Errorf("%s: got %v/%v, want %v/%v", tt.name, raise, unknown, tt.raise, tt.unknown)
		}
	}
}
