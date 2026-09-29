package collector

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
)

// CollectKernelRelease reads the running kernel's release string (what
// `uname -r` prints, e.g. "6.8.0-45-generic") from the procfs file
// sys/kernel/osrelease. It is a plain file read: the agent never executes
// uname or anything else.
//
// procFS is the target's procfs (target.ProcFiles). In the Docker
// deployment that is the agent container's own /proc, which is correct
// for the host: the kernel release is global to the kernel, not
// namespaced, so every container on a host sees the host kernel's
// release. /host/proc is deliberately not used: the Docker deployment binds
// the host's / non-recursively, so /host/proc is an empty directory.
func CollectKernelRelease(procFS fs.FS) (string, error) {
	const p = "sys/kernel/osrelease"
	b, err := fs.ReadFile(procFS, p)
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
