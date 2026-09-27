package collector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CollectArch returns the host's native architecture in Debian naming
// ("amd64", "arm64", "armhf", ...), which is what package arches,
// software_versions.arch and distro advisories use.
//
// Sources, in order:
//
//  1. The Architecture of the installed "dpkg" package. dpkg is Essential
//     and built for the native architecture, so its arch IS dpkg's native
//     arch (what `dpkg --print-architecture` prints), and reading it from
//     the already-collected inventory costs nothing. This is preferred
//     because it describes the userland: a 64-bit kernel can run a 32-bit
//     userland, and it is the userland's packages we match.
//  2. procRoot/sys/kernel/arch (Linux 6.1+; what `uname -m` prints),
//     mapped to Debian naming. Used on hosts without dpkg, or when the
//     package collector failed.
//
// pkgs may be nil (no package source succeeded); procRoot may be "" (no
// live procfs).
func CollectArch(pkgs []Package, procRoot string) (string, error) {
	for _, p := range pkgs {
		if p.Name == "dpkg" && p.Ecosystem == "deb" && p.Arch != "" && p.Arch != "all" {
			return p.Arch, nil
		}
	}
	if procRoot == "" {
		return "", errors.New("no dpkg package and no procfs to read the kernel arch from")
	}
	p := filepath.Join(procRoot, "sys", "kernel", "arch")
	b, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("no dpkg package, and read %s: %w", p, err)
	}
	m := strings.TrimSpace(string(b))
	if m == "" || len(m) > 32 || strings.ContainsAny(m, " \t\n\x00/") {
		return "", fmt.Errorf("%s: implausible arch %q", p, m)
	}
	return debianArch(m), nil
}

// unameToDebian maps `uname -m` machine names to Debian architecture names.
// Unknown names pass through unchanged.
var unameToDebian = map[string]string{
	"x86_64":  "amd64",
	"aarch64": "arm64",
	"armv7l":  "armhf",
	"armv6l":  "armel",
	"i386":    "i386",
	"i486":    "i386",
	"i586":    "i386",
	"i686":    "i386",
	"ppc64le": "ppc64el",
	"s390x":   "s390x",
	"riscv64": "riscv64",
}

func debianArch(machine string) string {
	if a, ok := unameToDebian[machine]; ok {
		return a
	}
	return machine
}
