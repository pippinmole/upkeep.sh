package purl

import (
	"testing"

	"github.com/pippinmole/upkeep.sh/server/internal/inventory"
)

var testIndex = ReleaseIndex{
	{"debian", "12"}:    "bookworm",
	{"debian", "13"}:    "trixie",
	{"ubuntu", "22.04"}: "jammy",
}

var (
	bookworm = OSRelease{ID: "debian", VersionID: "12", VersionCodename: "bookworm"}
	alpine   = OSRelease{ID: "alpine", VersionID: "3.20.3"}
)

func TestMap(t *testing.T) {
	type want struct {
		eco, distro, release string
		item                 inventory.Item
		known, fromPURL      bool
	}
	tests := []struct {
		name string
		purl string
		os   OSRelease
		want want
	}{
		{
			"deb with upstream name", "pkg:deb/debian/libssl3@3.0.15-1~deb12u1?arch=amd64&upstream=openssl&distro=debian-12",
			bookworm,
			want{
				"deb", "debian", "bookworm",
				inventory.Item{
					Name: "libssl3", Version: "3.0.15-1~deb12u1", Arch: "amd64",
					Source: "openssl", SourceVersion: "3.0.15-1~deb12u1",
				},
				true, false,
			},
		},
		{
			"deb upstream with version, epoch in version (Syft)",
			"pkg:deb/debian/login@1%3A4.13%2Bdfsg1-1%2Bb1?arch=amd64&upstream=shadow%401%3A4.13%2Bdfsg1-1&distro=debian-12",
			bookworm,
			want{
				"deb", "debian", "bookworm",
				inventory.Item{
					Name: "login", Version: "1:4.13+dfsg1-1+b1", Arch: "amd64",
					Source: "shadow", SourceVersion: "1:4.13+dfsg1-1",
				},
				true, false,
			},
		},
		{
			"deb epoch qualifier (Trivy) folded into version",
			"pkg:deb/debian/login@4.13%2Bdfsg1-1%2Bb1?arch=amd64&epoch=1&distro=debian-12",
			bookworm,
			want{
				"deb", "debian", "bookworm",
				inventory.Item{
					Name: "login", Version: "1:4.13+dfsg1-1+b1", Arch: "amd64",
					Source: "login", SourceVersion: "1:4.13+dfsg1-1+b1", SourceInferred: true,
				},
				true, false,
			},
		},
		{
			"deb epoch 0 dropped", "pkg:deb/debian/bash@5.2.15-2%2Bb7?arch=arm64&epoch=0",
			bookworm,
			want{
				"deb", "debian", "bookworm",
				inventory.Item{
					Name: "bash", Version: "5.2.15-2+b7", Arch: "arm64",
					Source: "bash", SourceVersion: "5.2.15-2+b7", SourceInferred: true,
				},
				true, false,
			},
		},
		{
			"deb without os-release: qualifier + index", "pkg:deb/debian/libc6@2.36-9%2Bdeb12u9?arch=amd64&upstream=glibc&distro=debian-12",
			OSRelease{},
			want{
				"deb", "debian", "bookworm",
				inventory.Item{
					Name: "libc6", Version: "2.36-9+deb12u9", Arch: "amd64",
					Source: "glibc", SourceVersion: "2.36-9+deb12u9",
				},
				true, true,
			},
		},
		{
			"ubuntu os-release without codename resolves via index", "pkg:deb/ubuntu/bash@5.1-6ubuntu1.1?arch=amd64&distro=ubuntu-22.04",
			OSRelease{ID: "ubuntu", VersionID: "22.04"},
			want{
				"deb", "ubuntu", "jammy",
				inventory.Item{
					Name: "bash", Version: "5.1-6ubuntu1.1", Arch: "amd64",
					Source: "bash", SourceVersion: "5.1-6ubuntu1.1", SourceInferred: true,
				},
				true, false,
			},
		},
		{
			"apk: release is major.minor", "pkg:apk/alpine/musl@1.2.5-r0?arch=x86_64&distro=3.20.3",
			alpine,
			want{
				"apk", "alpine", "3.20",
				inventory.Item{
					Name: "musl", Version: "1.2.5-r0", Arch: "x86_64",
					Source: "musl", SourceVersion: "1.2.5-r0", SourceInferred: true,
				},
				true, false,
			},
		},
		{
			"apk origin, version-only qualifier fallback", "pkg:apk/alpine/libcrypto3@3.3.2-r0?arch=aarch64&upstream=openssl&distro=3.20.3",
			OSRelease{},
			want{
				"apk", "alpine", "3.20",
				inventory.Item{
					Name: "libcrypto3", Version: "3.3.2-r0", Arch: "aarch64",
					Source: "openssl", SourceVersion: "3.3.2-r0",
				},
				true, true,
			},
		},
		{
			"rpm source rpm and epoch", "pkg:rpm/redhat/openssl-libs@3.0.7-27.el9?arch=x86_64&epoch=1&upstream=openssl-3.0.7-27.el9.src.rpm&distro=rhel-9.4",
			OSRelease{ID: "rhel", VersionID: "9.4"},
			want{
				"rpm", "rhel", "9.4",
				inventory.Item{
					Name: "openssl-libs", Version: "1:3.0.7-27.el9", Arch: "x86_64",
					Source: "openssl", SourceVersion: "3.0.7-27.el9",
				},
				true, false,
			},
		},
		{
			"npm scoped", "pkg:npm/%40babel/core@7.24.0",
			bookworm,
			want{
				"npm", "", "",
				inventory.Item{
					Name: "@babel/core", Version: "7.24.0",
					Source: "@babel/core", SourceVersion: "7.24.0", SourceInferred: true,
				},
				true, false,
			},
		},
		{
			"pypi normalised", "pkg:pypi/Typing_Extensions@4.9.0",
			bookworm,
			want{
				"pypi", "", "",
				inventory.Item{
					Name: "typing-extensions", Version: "4.9.0",
					Source: "typing-extensions", SourceVersion: "4.9.0", SourceInferred: true,
				},
				true, false,
			},
		},
		{
			"golang module path, version verbatim", "pkg:golang/github.com/sirupsen/logrus@v1.9.3",
			alpine,
			want{
				"golang", "", "",
				inventory.Item{
					Name: "github.com/sirupsen/logrus", Version: "v1.9.3",
					Source: "github.com/sirupsen/logrus", SourceVersion: "v1.9.3", SourceInferred: true,
				},
				true, false,
			},
		},
		{
			"maven group:artifact", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar",
			OSRelease{},
			want{
				"maven", "", "",
				inventory.Item{
					Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1",
					Source: "org.apache.logging.log4j:log4j-core", SourceVersion: "2.14.1", SourceInferred: true,
				},
				true, false,
			},
		},
		{
			"unknown type is kept", "pkg:bitnami/redis@7.2.4?arch=arm64",
			bookworm,
			want{
				"bitnami", "", "",
				inventory.Item{
					Name: "redis", Version: "7.2.4", Arch: "arm64",
					Source: "redis", SourceVersion: "7.2.4", SourceInferred: true,
				},
				false, false,
			},
		},
		{
			"unknown type with namespace", "pkg:huggingface/microsoft/deberta-v3-base@559062ad",
			OSRelease{},
			want{
				"huggingface", "", "",
				inventory.Item{
					Name: "microsoft/deberta-v3-base", Version: "559062ad",
					Source: "microsoft/deberta-v3-base", SourceVersion: "559062ad", SourceInferred: true,
				},
				false, false,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := MapString(tc.purl, tc.os, testIndex)
			if err != nil {
				t.Fatal(err)
			}
			w := tc.want
			if got.Ecosystem != w.eco || got.Distro != w.distro || got.Release != w.release ||
				got.Item != w.item || got.KnownType != w.known || got.DistroFromPURL != w.fromPURL {
				t.Errorf("\n got %+v\nwant %+v", got, w)
			}
		})
	}
}

func TestMapErrors(t *testing.T) {
	for _, in := range []string{
		"pkg:deb/debian/bash",                  // no version
		"pkg:deb/debian/bash@5.2?epoch=x",      // bad epoch
		"pkg:npm/left-pad@1.0.0%00",            // NUL
		"pkg:deb/debian/bash@5.2?distro=%00x1", // NUL in scope
	} {
		if p, err := MapString(in, OSRelease{}, nil); err == nil {
			t.Errorf("MapString(%q) = %+v, want error", in, p)
		}
	}
}

func TestReleaseFor(t *testing.T) {
	tests := []struct {
		os   OSRelease
		want string
	}{
		{bookworm, "bookworm"},
		{OSRelease{ID: "debian", VersionID: "12"}, "bookworm"},
		{OSRelease{ID: "debian", VersionID: "12.7"}, "bookworm"}, // point release
		{OSRelease{ID: "debian", VersionID: "99"}, ""},           // unknown: never the number
		{OSRelease{ID: "debian"}, ""},                            // sid / testing without VERSION_ID
		{OSRelease{ID: "Ubuntu", VersionID: "22.04", VersionCodename: "jammy"}, "jammy"},
		{alpine, "3.20"},
		{OSRelease{ID: "alpine", VersionID: "3.21_alpha20240807"}, "3.21"},
		{OSRelease{ID: "rocky", VersionID: "9.4"}, "9.4"},
		{OSRelease{}, ""},
	}
	for _, tc := range tests {
		if got := ReleaseFor(tc.os, testIndex); got != tc.want {
			t.Errorf("ReleaseFor(%+v) = %q, want %q", tc.os, got, tc.want)
		}
	}
}

func TestOSFromQualifier(t *testing.T) {
	tests := []struct {
		purl string
		want OSRelease
		ok   bool
	}{
		{"pkg:deb/debian/a@1?distro=debian-12", OSRelease{ID: "debian", VersionID: "12"}, true},
		{"pkg:deb/ubuntu/a@1?distro=ubuntu-22.04", OSRelease{ID: "ubuntu", VersionID: "22.04"}, true},
		{"pkg:apk/alpine/a@1?distro=alpine-3.20.3", OSRelease{ID: "alpine", VersionID: "3.20.3"}, true},
		{"pkg:apk/alpine/a@1?distro=3.20.3", OSRelease{ID: "alpine", VersionID: "3.20.3"}, true},
		{"pkg:deb/debian/a@1?distro=bookworm", OSRelease{ID: "debian", VersionCodename: "bookworm"}, true},
		{"pkg:rpm/opensuse/a@1?distro=opensuse-leap-15.5", OSRelease{ID: "opensuse-leap", VersionID: "15.5"}, true},
		{"pkg:deb/debian/a@1", OSRelease{}, false},
	}
	for _, tc := range tests {
		p, err := Parse(tc.purl)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := OSFromQualifier(p)
		if got != tc.want || ok != tc.ok {
			t.Errorf("OSFromQualifier(%q) = %+v, %v; want %+v, %v", tc.purl, got, ok, tc.want, tc.ok)
		}
	}
}

func TestDistroScoped(t *testing.T) {
	for eco, want := range map[string]bool{"deb": true, "apk": true, "rpm": true, "npm": false, "bitnami": false} {
		if got := DistroScoped(eco); got != want {
			t.Errorf("DistroScoped(%q) = %v", eco, got)
		}
	}
}

func TestUpstreamSRPM(t *testing.T) {
	for in, want := range map[string][2]string{
		"openssl-3.0.7-27.el9.src.rpm":         {"openssl", "3.0.7-27.el9"},
		"python3-pip-21.2.3-8.el9.src.rpm":     {"python3-pip", "21.2.3-8.el9"},
		"glibc":                                {"glibc", ""},
		"kernel-5.14.0-427.13.1.el9_4.src.rpm": {"kernel", "5.14.0-427.13.1.el9_4"},
	} {
		n, v, ok := upstreamSRPM(in)
		if !ok || n != want[0] || v != want[1] {
			t.Errorf("upstreamSRPM(%q) = %q, %q, %v", in, n, v, ok)
		}
	}
}
