// Package goversion orders Go module versions: semantic versions with a
// "v" prefix, including pseudo-versions (v0.0.0-20210101120000-abcdef123456)
// and "+incompatible", as the go command does. Advisory matching
// (docs/DOMAIN_MODEL.md §2.5) compares installed Go modules against OSV
// Go ranges (type SEMVER) here.
//
// The ordering is golang.org/x/mod/semver's, the go command's own
// implementation (BSD-3-Clause, no dependencies of its own, already in
// the module graph through Syft), tested with its test table
// (testdata/). This package only canonicalises the spellings that meet
// in matching:
//
//   - OSV's Go ranges drop the "v" ("1.2.3"); module versions have it.
//     SBOMs differ (docker scout writes "0.1.0" for v0.1.0), so a missing
//     "v" is added.
//   - The standard library ("stdlib", "toolchain") is versioned by Go
//     release: "go1.22.3" (Syft) or "1.22.3"; the "go" prefix is dropped.
//     Go release candidates and betas ("go1.21rc2", "1.21beta1") become
//     the semver form OSV uses for them ("v1.21.0-rc.2").
//   - "+incompatible" is build metadata: v2.0.0+incompatible orders as
//     v2.0.0, as in the go command.
package goversion

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

// goRelease is a Go toolchain pre-release: 1.21rc2, 1.21.0rc1, 1.9beta2.
var goRelease = regexp.MustCompile(`^v(\d+)\.(\d+)(?:\.(\d+))?(rc|beta)(\d+)$`)

// Canonical returns the semver form of a Go module or Go release version
// ("v" + x/mod/semver syntax), or an error if it is not one.
func Canonical(s string) (string, error) {
	v := strings.TrimSpace(s)
	v = strings.TrimPrefix(v, "go")
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if m := goRelease.FindStringSubmatch(v); m != nil {
		patch := m[3]
		if patch == "" {
			patch = "0"
		}
		v = fmt.Sprintf("v%s.%s.%s-%s.%s", m[1], m[2], patch, m[4], m[5])
	}
	if !semver.IsValid(v) {
		return "", fmt.Errorf("goversion: invalid version %q", s)
	}
	return v, nil
}

// Valid reports whether s is a Go module or Go release version.
func Valid(s string) bool {
	_, err := Canonical(s)
	return err == nil
}

// Compare returns -1, 0 or +1 as a is older than, equal to or newer than
// b, or an error if either is invalid.
func Compare(a, b string) (int, error) {
	ca, err := Canonical(a)
	if err != nil {
		return 0, err
	}
	cb, err := Canonical(b)
	if err != nil {
		return 0, err
	}
	return semver.Compare(ca, cb), nil
}
