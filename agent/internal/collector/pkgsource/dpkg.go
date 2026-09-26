package pkgsource

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/pippinmole/upkeep.sh/agent/internal/collector"
	"github.com/pippinmole/upkeep.sh/agent/internal/detect"
	"github.com/pippinmole/upkeep.sh/agent/internal/target"
)

// dpkgStatusPath is the dpkg database, relative to the target's root.
const dpkgStatusPath = "var/lib/dpkg/status"

// Dpkg reads installed packages from dpkg's status(5) database on
// Debian-like Linux (Debian, Ubuntu and derivatives).
type Dpkg struct{}

func (Dpkg) Name() string      { return "deb_packages" }
func (Dpkg) Ecosystem() string { return "deb" }

func (Dpkg) Applies(o detect.OS) bool {
	return o.Family == detect.FamilyLinux && o.Like("debian", "ubuntu")
}

func (Dpkg) Collect(_ context.Context, t target.Target) ([]collector.Package, error) {
	f, err := t.FS().Open(dpkgStatusPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pkgs, err := parseDpkgStatus(f)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", dpkgStatusPath, err)
	}
	return pkgs, nil
}

// parseDpkgStatus returns every package in the "installed" state. Records
// are deb822 paragraphs separated by blank lines; continuation lines (which
// start with whitespace, e.g. Description, Conffiles) never match a field
// prefix below, so they are ignored without special handling.
func parseDpkgStatus(r io.Reader) ([]collector.Package, error) {
	var pkgs []collector.Package
	var name, version, arch, status, source string

	flush := func() {
		if name != "" && isInstalled(status) {
			srcName, srcVersion := parseSource(source, name, version)
			pkgs = append(pkgs, collector.Package{
				Name: name, Version: version, Arch: arch,
				Source: srcName, SourceVersion: srcVersion,
			})
		}
		name, version, arch, status, source = "", "", "", "", ""
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if v, ok := field(line, "Package"); ok {
			name = v
		} else if v, ok := field(line, "Version"); ok {
			version = v
		} else if v, ok := field(line, "Architecture"); ok {
			arch = v
		} else if v, ok := field(line, "Status"); ok {
			status = v
		} else if v, ok := field(line, "Source"); ok {
			source = v
		}
	}
	flush() // last record may have no trailing blank line
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return pkgs, nil
}

func field(line, key string) (string, bool) {
	v, ok := strings.CutPrefix(line, key+":")
	if !ok {
		return "", false
	}
	return strings.TrimSpace(v), true
}

// isInstalled checks the third word of "Status: want flag status" (e.g.
// "install ok installed"). A substring match on "installed" would also
// accept "half-installed" and "not-installed", which are not on disk as a
// working package.
func isInstalled(status string) bool {
	f := strings.Fields(status)
	return len(f) == 3 && f[2] == "installed"
}

// parseSource resolves a package's source name and version from its
// Source: field, which dpkg writes in one of three forms:
//
//	(absent)                 source = binary name, source version = binary version
//	Source: openssl          source version = binary version
//	Source: openssl (3.0.2)  explicit source version, e.g. binNMUs ("+b1")
func parseSource(field, binName, binVersion string) (name, version string) {
	if field == "" {
		return binName, binVersion
	}
	name, rest, hasVersion := strings.Cut(field, " ")
	if !hasVersion {
		return name, binVersion
	}
	rest = strings.TrimSpace(rest)
	if v, ok := strings.CutPrefix(rest, "("); ok {
		if v, ok := strings.CutSuffix(v, ")"); ok && strings.TrimSpace(v) != "" {
			return name, strings.TrimSpace(v)
		}
	}
	// Malformed version part: keep the name, fall back to the binary
	// version rather than send garbage.
	return name, binVersion
}
