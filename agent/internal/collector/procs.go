package collector

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcessUnits maps every pid under procRoot to the systemd system service
// it runs under, from /proc/<pid>/cgroup (world-readable, no ptrace access
// needed). Processes outside system.slice (user sessions, container
// scopes, kernel threads) are absent. This is how service running state is
// read without D-Bus or systemctl.
func ProcessUnits(procRoot string) map[int]string {
	out := map[int]string{}
	for _, pid := range listPIDs(procRoot) {
		b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
		if err != nil {
			continue
		}
		if unit := unitFromCgroup(string(b)); unit != "" {
			out[pid] = unit
		}
	}
	return out
}

// unitFromCgroup extracts the system service from a /proc/<pid>/cgroup
// file. Each line is "hierarchy:controllers:path"; on cgroup v2 there is
// one "0::" line, on v1 the name=systemd hierarchy carries the path. The
// service is the first *.service segment after "system.slice", skipping
// nested slices ("system.slice/system-getty.slice/getty@tty1.service").
//
// The path is relative to the reader's cgroup namespace. The agent runs in
// its own container cgroup namespace, so host processes read as
// "0::/../../system.slice/ssh.service"; searching for the system.slice
// segment rather than anchoring at the root handles that.
func unitFromCgroup(content string) string {
	for _, line := range strings.Split(content, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		segs := strings.Split(parts[2], "/")
		for i, seg := range segs {
			if seg != "system.slice" {
				continue
			}
			for _, s := range segs[i+1:] {
				if strings.HasSuffix(s, ".slice") {
					continue
				}
				if strings.HasSuffix(s, ".service") {
					return s
				}
				break
			}
			break
		}
	}
	return ""
}
