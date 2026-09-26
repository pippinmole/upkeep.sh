package collector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CollectKernelRelease reads the running kernel's release string (what
// `uname -r` prints, e.g. "6.8.0-45-generic") from procRoot's
// sys/kernel/osrelease. It is a plain file read: the agent never executes
// uname or anything else.
//
// procRoot is the target's live procfs (target.LiveProc). In the Docker
// deployment that is the agent container's own /proc, which is correct
// for the host: the kernel release is global to the kernel, not
// namespaced, so every container on a host sees the host kernel's
// release. The /:/host bind mount's host/proc is deliberately not used: a
// non-recursive bind (or a host without /proc mounted there) would show an
// empty directory.
func CollectKernelRelease(procRoot string) (string, error) {
	p := filepath.Join(procRoot, "sys", "kernel", "osrelease")
	b, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", p, err)
	}
	rel := strings.TrimSpace(string(b))
	if rel == "" {
		return "", errors.New(p + " is empty")
	}
	if len(rel) > 256 || strings.ContainsAny(rel, " \t\n\x00") {
		return "", fmt.Errorf("%s: implausible kernel release %q", p, rel)
	}
	return rel, nil
}
