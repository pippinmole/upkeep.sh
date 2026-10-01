package collector

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
)

// Debian/Ubuntu's pending-reboot flag files (written by update-notifier /
// unattended-upgrades). They live in /run: /var/run is an *absolute*
// symlink to /run on modern hosts, which under a /host bind mount resolves
// inside the agent's container instead of the host, so reading
// var/run/... through the host root silently finds nothing. var/run is
// kept only as a fallback for old hosts where it is a real directory.
var (
	rebootRequiredPaths     = []string{"run/reboot-required", "var/run/reboot-required"}
	rebootRequiredPkgsPaths = []string{"run/reboot-required.pkgs", "var/run/reboot-required.pkgs"}
)

// Values of Reboot.Source (the wire's reboot_required_source).
const (
	// RebootSourceFlagFile: the host's /run/reboot-required was readable
	// (present or, authoritatively, absent). Newer installed kernels are
	// still OR-ed in.
	RebootSourceFlagFile = "flag_file"
	// RebootSourceKernel: derived from the running kernel vs the kernels
	// installed in dpkg (the flag file wasn't visible, or was absent while
	// a newer kernel is installed).
	RebootSourceKernel = "kernel"
)

// ErrRebootUnknown means neither source could decide: the flag file isn't
// visible and the running kernel isn't a dpkg-installed one (a VM/container
// kernel, WSL, a custom build) or the package inventory is unavailable.
var ErrRebootUnknown = errors.New("pending reboot unknown")

// Reboot is the reboot_required collector's result.
type Reboot struct {
	Required bool
	// Packages that triggered it: the flag file's .pkgs list, plus any
	// newer installed kernel image packages.
	Packages []string
	Source   string
}

// CollectRebootRequired reports whether the host has a pending reboot,
// from two signals (runVisible: whether the host's /run is visible at all,
// see target.Local.RunVisible):
//
//   - the flag file /run/reboot-required{,.pkgs}, when the host's /run is
//     visible (remote targets, bare metal, and a recursive host mount; the
//     Docker deployment's non-recursive /host doesn't carry /run, whose
//     tmpfs also holds the host's control sockets). A missing flag file is
//     then the normal "no reboot pending".
//   - the kernels: a reboot is pending when dpkg has a newer kernel image
//     of the running kernel's flavor installed than the one running
//     (Debian version ordering). runningKernel is the release from
//     /proc/sys/kernel/osrelease; pkgs is the dpkg inventory, nil when it
//     wasn't collected.
//
// When the flag file isn't visible and the kernel can't decide either, it
// returns ErrRebootUnknown rather than a false "no reboot pending".
func CollectRebootRequired(fsys fs.FS, runVisible bool, runningKernel string, pkgs []Package) (Reboot, error) {
	kernelReq, kernelPkgs, kernelErr := kernelRebootRequired(runningKernel, pkgs)

	if !runVisible {
		if kernelErr != nil {
			return Reboot{}, fmt.Errorf("%w: /run/reboot-required isn't visible (the host's /run isn't mounted, by design) and %w", ErrRebootUnknown, kernelErr)
		}
		return Reboot{Required: kernelReq, Packages: kernelPkgs, Source: RebootSourceKernel}, nil
	}

	req, flagPkgs, err := readRebootFlag(fsys)
	if err != nil {
		return Reboot{}, err
	}
	r := Reboot{Required: req, Packages: flagPkgs, Source: RebootSourceFlagFile}
	if kernelErr == nil && kernelReq {
		if !req {
			r.Source = RebootSourceKernel
		}
		r.Required = true
		for _, p := range kernelPkgs {
			if !slices.Contains(r.Packages, p) {
				r.Packages = append(r.Packages, p)
			}
		}
	}
	return r, nil
}

func readRebootFlag(fsys fs.FS) (bool, []string, error) {
	required := false
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
	var pkgs []string
	for _, p := range rebootRequiredPkgsPaths {
		f, openErr := fsys.Open(p)
		if openErr != nil {
			continue // the package list is optional detail
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" && !slices.Contains(pkgs, line) {
				pkgs = append(pkgs, line)
			}
		}
		f.Close()
		break
	}
	return true, pkgs, nil
}
