package collector

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"strings"
)

// Debian/Ubuntu's pending-reboot flag files (written by update-notifier /
// unattended-upgrades). They live in /run: /var/run is an *absolute*
// symlink to /run on modern hosts, which under a /:/host bind mount
// resolves inside the agent's container instead of the host, so reading
// var/run/... through the host root silently finds nothing. var/run is
// kept only as a fallback for old hosts where it is a real directory.
var (
	rebootRequiredPaths     = []string{"run/reboot-required", "var/run/reboot-required"}
	rebootRequiredPkgsPaths = []string{"run/reboot-required.pkgs", "var/run/reboot-required.pkgs"}
)

// CollectRebootRequired reports whether the host has a pending reboot and,
// if available, which packages triggered it. A missing flag file is the
// normal "no reboot pending" case, not an error.
func CollectRebootRequired(fsys fs.FS) (required bool, pkgs []string, err error) {
	for _, p := range rebootRequiredPaths {
		_, statErr := fs.Stat(fsys, p)
		if statErr == nil {
			required = true
			break
		}
		if !errors.Is(statErr, fs.ErrNotExist) {
			return false, nil, fmt.Errorf("stat %s: %w", p, statErr)
		}
	}
	if !required {
		return false, nil, nil
	}

	for _, p := range rebootRequiredPkgsPaths {
		f, openErr := fsys.Open(p)
		if openErr != nil {
			continue // the package list is optional detail
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				pkgs = append(pkgs, line)
			}
		}
		f.Close()
		break
	}
	return required, pkgs, nil
}
