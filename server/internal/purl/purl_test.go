package purl

import (
	"maps"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in   string
		want PURL
	}{
		{"pkg:deb/debian/libssl3@3.0.15-1~deb12u1?arch=amd64&upstream=openssl&distro=debian-12",
			PURL{Type: "deb", Namespace: "debian", Name: "libssl3", Version: "3.0.15-1~deb12u1",
				Qualifiers: map[string]string{"arch": "amd64", "upstream": "openssl", "distro": "debian-12"}}},
		// Syft percent-encodes the epoch colon and '+'.
		{"pkg:deb/debian/libgcrypt20@1.10.1-3?arch=arm64&upstream=libgcrypt20&distro=debian-12",
			PURL{Type: "deb", Namespace: "debian", Name: "libgcrypt20", Version: "1.10.1-3",
				Qualifiers: map[string]string{"arch": "arm64", "upstream": "libgcrypt20", "distro": "debian-12"}}},
		{"pkg:deb/debian/login@1%3A4.13%2Bdfsg1-1%2Bb1?arch=amd64&upstream=shadow%404.13%2Bdfsg1-1&distro=debian-12",
			PURL{Type: "deb", Namespace: "debian", Name: "login", Version: "1:4.13+dfsg1-1+b1",
				Qualifiers: map[string]string{"arch": "amd64", "upstream": "shadow@4.13+dfsg1-1", "distro": "debian-12"}}},
		{"pkg:apk/alpine/musl@1.2.5-r0?arch=x86_64&distro=3.20.3",
			PURL{Type: "apk", Namespace: "alpine", Name: "musl", Version: "1.2.5-r0",
				Qualifiers: map[string]string{"arch": "x86_64", "distro": "3.20.3"}}},
		{"pkg:npm/%40babel/core@7.24.0",
			PURL{Type: "npm", Namespace: "@babel", Name: "core", Version: "7.24.0"}},
		// Unencoded scope: the '@' before the '/' is not the version separator.
		{"pkg:npm/@types/node@20.11.5",
			PURL{Type: "npm", Namespace: "@types", Name: "node", Version: "20.11.5"}},
		{"pkg:golang/github.com/sirupsen/logrus@v1.9.3",
			PURL{Type: "golang", Namespace: "github.com/sirupsen", Name: "logrus", Version: "v1.9.3"}},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar",
			PURL{Type: "maven", Namespace: "org.apache.logging.log4j", Name: "log4j-core", Version: "2.14.1",
				Qualifiers: map[string]string{"type": "jar"}}},
		{"PKG://PyPI/Django@4.2.0#src/django",
			PURL{Type: "pypi", Name: "Django", Version: "4.2.0", Subpath: "src/django"}},
		{"pkg:generic/openssl", PURL{Type: "generic", Name: "openssl"}},
		// Empty qualifier values are dropped; keys lowercased.
		{"pkg:cargo/serde@1.0.197?Arch=&Foo=bar", PURL{Type: "cargo", Name: "serde", Version: "1.0.197",
			Qualifiers: map[string]string{"foo": "bar"}}},
	}
	for _, tc := range tests {
		got, err := Parse(tc.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", tc.in, err)
			continue
		}
		if tc.want.Qualifiers == nil {
			tc.want.Qualifiers = got.Qualifiers
			if len(got.Qualifiers) != 0 {
				t.Errorf("Parse(%q): unexpected qualifiers %v", tc.in, got.Qualifiers)
			}
		}
		if got.Type != tc.want.Type || got.Namespace != tc.want.Namespace || got.Name != tc.want.Name ||
			got.Version != tc.want.Version || got.Subpath != tc.want.Subpath ||
			!maps.Equal(got.Qualifiers, tc.want.Qualifiers) {
			t.Errorf("Parse(%q)\n got %+v\nwant %+v", tc.in, got, tc.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{
		"",
		"deb/debian/bash@5.2",         // no scheme
		"pkg:deb",                     // no name
		"pkg:/bash@1",                 // no type
		"pkg:deb/debian/bash@5%ZZ",    // bad escape in version
		"pkg:deb/debian/bash@5?=x",    // empty qualifier key
		"pkg:deb/debian/bash@5?a=%G1", // bad escape in qualifier
	} {
		if p, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) = %+v, want error", in, p)
		}
	}
}
