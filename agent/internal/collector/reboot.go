package collector

import (
	"bufio"
	"os"
	"strings"
)

const DefaultRebootRequiredPath = "/host/var/run/reboot-required"
const DefaultRebootRequiredPkgsPath = "/host/var/run/reboot-required.pkgs"

// CollectRebootRequired reports whether the host has a pending reboot
// (Debian/Ubuntu's needrestart / unattended-upgrades convention) and, if
// available, which packages triggered it.
func CollectRebootRequired(flagPath, pkgsPath string) (required bool, pkgs []string) {
	if _, err := os.Stat(flagPath); err != nil {
		return false, nil
	}
	required = true

	f, err := os.Open(pkgsPath)
	if err != nil {
		return required, nil
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			pkgs = append(pkgs, line)
		}
	}
	return required, pkgs
}
