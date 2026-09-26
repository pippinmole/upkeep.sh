package collector

import (
	"bufio"
	"io"
	"os"
	"strings"
)

// DefaultDpkgStatusPath is where the host's dpkg database is mounted inside
// the agent container (via the read-only /:/host bind mount).
const DefaultDpkgStatusPath = "/host/var/lib/dpkg/status"

// CollectPackages parses a dpkg status(5) file and returns every package
// currently in the "installed" state.
func CollectPackages(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseDpkgStatus(f)
}

func parseDpkgStatus(r io.Reader) ([]Package, error) {
	var pkgs []Package
	var name, version, arch, status string

	flush := func() {
		if name != "" && strings.Contains(status, "installed") {
			pkgs = append(pkgs, Package{Name: name, Version: version, Arch: arch})
		}
		name, version, arch, status = "", "", "", ""
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		switch {
		case strings.HasPrefix(line, "Package:"):
			name = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
		case strings.HasPrefix(line, "Version:"):
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		case strings.HasPrefix(line, "Architecture:"):
			arch = strings.TrimSpace(strings.TrimPrefix(line, "Architecture:"))
		case strings.HasPrefix(line, "Status:"):
			status = strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
		}
	}
	flush() // last record has no trailing blank line
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return pkgs, nil
}
