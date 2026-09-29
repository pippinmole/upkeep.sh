package collector

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/pippinmole/upkeep.sh/agent/internal/debversion"
)

// kernelImagePrefixes name the packages holding one kernel release:
// linux-image-<release> (Debian, Ubuntu signed) and
// linux-image-unsigned-<release> (Ubuntu). Meta packages such as
// linux-image-generic or linux-image-amd64 have no release in the name
// (it doesn't start with a digit) and are ignored.
var kernelImagePrefixes = []string{"linux-image-unsigned-", "linux-image-"}

// kernelRelease returns the kernel release a package installs, or "".
func kernelRelease(name string) string {
	for _, p := range kernelImagePrefixes {
		if rel, ok := strings.CutPrefix(name, p); ok {
			if rel != "" && rel[0] >= '0' && rel[0] <= '9' {
				return rel
			}
			return ""
		}
	}
	return ""
}

// kernelFlavour is the part of a release after its version: "generic" in
// 6.8.0-45-generic, "cloud-amd64" in 6.1.0-18-cloud-amd64, "rpi-v8" in
// 6.6.31+rpt-rpi-v8. A reboot is only pending for a newer kernel of the
// same flavour: installing linux-image-lowlatency next to a running
// generic kernel doesn't change what boots by default.
func kernelFlavour(release string) string {
	parts := strings.Split(release, "-")
	if len(parts) < 2 {
		return ""
	}
	rest := parts[1:]
	if strings.Trim(rest[0], "0123456789") == "" && len(rest) > 1 {
		rest = rest[1:] // the ABI number (Debian/Ubuntu)
	}
	return strings.Join(rest, "-")
}

// kernelRebootRequired decides from dpkg alone whether a newer kernel than
// the running one is installed. It errors when it can't decide: no
// running kernel, no dpkg inventory, or a running kernel that isn't a
// dpkg-installed one.
func kernelRebootRequired(running string, pkgs []Package) (bool, []string, error) {
	if running == "" {
		return false, nil, errors.New("the running kernel is unknown")
	}
	if pkgs == nil {
		return false, nil, errors.New("the dpkg inventory isn't available")
	}
	type kpkg struct {
		name    string
		version debversion.Version
	}
	var runningVer *debversion.Version
	var sameFlavour []kpkg
	flavour := kernelFlavour(running)
	for _, p := range pkgs {
		if p.Ecosystem != "" && p.Ecosystem != "deb" {
			continue
		}
		rel := kernelRelease(p.Name)
		if rel == "" {
			continue
		}
		v, err := debversion.Parse(p.Version)
		if err != nil {
			continue
		}
		if rel == running {
			if runningVer == nil || debversion.Compare(v, *runningVer) > 0 {
				runningVer = &v
			}
			continue
		}
		if kernelFlavour(rel) == flavour {
			sameFlavour = append(sameFlavour, kpkg{p.Name, v})
		}
	}
	if runningVer == nil {
		return false, nil, fmt.Errorf("the running kernel %s isn't a dpkg-installed kernel", running)
	}
	var newer []string
	for _, k := range sameFlavour {
		if debversion.Compare(k.version, *runningVer) > 0 && !slices.Contains(newer, k.name) {
			newer = append(newer, k.name)
		}
	}
	slices.Sort(newer)
	return len(newer) > 0, newer, nil
}
