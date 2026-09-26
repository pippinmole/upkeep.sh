// Package detect works out what kind of host a target is (OS family and,
// on Linux, distro/version) and who it is (machine identity, hostname),
// purely by reading files through the target's filesystem.
//
// The agent is never told what a host is. Everything downstream (which
// package sources apply, which collectors run) is selected from the OS
// detected here, so that one agent can collect differently-typed hosts.
package detect

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strings"
)

// Family is the coarse OS family. Values match hosts.os_family in the
// planned schema (DOMAIN_MODEL.md §4.6).
type Family string

const (
	FamilyUnknown Family = ""
	FamilyLinux   Family = "linux"
	FamilyWindows Family = "windows"
	FamilyMacOS   Family = "macos"
)

// OS is the detected operating system of one target.
type OS struct {
	Family Family

	// Linux only, from os-release(5). Empty on other families: Windows and
	// macOS version detection belongs with their (not yet written)
	// collectors, which read the registry / SystemVersion.plist.
	ID        string   // "ubuntu", "debian"
	IDLike    []string // ID_LIKE, e.g. ["debian"] on Ubuntu
	VersionID string   // "22.04", "12"
	Codename  string   // "jammy", "bookworm"
}

// Like reports whether the OS is, or declares itself derived from, any of
// ids (matching ID, then ID_LIKE). This is how applicability is decided for
// distro-family facts, e.g. dpkg applies to anything Debian-like, which
// covers Ubuntu, Raspbian, Mint etc. without listing them.
func (o OS) Like(ids ...string) bool {
	for _, id := range ids {
		if o.ID == id || slices.Contains(o.IDLike, id) {
			return true
		}
	}
	return false
}

// ErrUnknownOS means no family's marker files were found under the target's
// root, e.g. a misconfigured host mount.
var ErrUnknownOS = errors.New("could not detect OS: no os-release, Windows or macOS markers found")

// osReleasePaths are tried in order, per os-release(5): /etc/os-release is
// usually a *relative* symlink to ../usr/lib/os-release, which resolves
// fine under a bind mount, but reading the fallback directly also covers
// hosts where it is absolute (and would escape the host root).
var osReleasePaths = []string{"etc/os-release", "usr/lib/os-release"}

// Marker files for non-Linux families. Only the family is detected for
// these; there are no Windows/macOS collectors yet, so detecting them
// results in every Linux collector reporting "skipped" rather than
// misreading a foreign filesystem.
const (
	windowsMarker = "Windows/System32"
	macOSMarker   = "System/Library/CoreServices/SystemVersion.plist"
)

// Detect determines the OS of the filesystem fsys (a target's root).
//
// Linux is checked first because it is the only family whose marker also
// carries version detail. A Linux os-release that exists but can't be read
// still yields FamilyLinux alongside the error, so the caller can report
// the failure without losing the family.
func Detect(fsys fs.FS) (OS, error) {
	for _, p := range osReleasePaths {
		f, err := fsys.Open(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return OS{Family: FamilyLinux}, fmt.Errorf("open %s: %w", p, err)
		}
		o, err := parseOSRelease(f)
		f.Close()
		if err != nil {
			return OS{Family: FamilyLinux}, fmt.Errorf("read %s: %w", p, err)
		}
		return o, nil
	}
	if exists(fsys, windowsMarker) {
		return OS{Family: FamilyWindows}, nil
	}
	if exists(fsys, macOSMarker) {
		return OS{Family: FamilyMacOS}, nil
	}
	return OS{}, ErrUnknownOS
}

func exists(fsys fs.FS, name string) bool {
	_, err := fs.Stat(fsys, name)
	return err == nil
}

func parseOSRelease(r io.Reader) (OS, error) {
	fields := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		fields[k] = unquote(v)
	}
	if err := sc.Err(); err != nil {
		return OS{}, err
	}
	o := OS{
		Family:    FamilyLinux,
		ID:        fields["ID"],
		VersionID: fields["VERSION_ID"],
		Codename:  fields["VERSION_CODENAME"],
	}
	if like := strings.Fields(fields["ID_LIKE"]); len(like) > 0 {
		o.IDLike = like
	}
	return o, nil
}

// unquote strips one layer of matching single or double quotes. os-release
// values are shell-style; the fields we read never contain escapes in
// practice, so full shell unquoting isn't worth it.
func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}
