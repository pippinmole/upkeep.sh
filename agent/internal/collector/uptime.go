package collector

import (
	"fmt"
	"io/fs"
	"strconv"
	"strings"
)

// CollectUptime reads whole seconds since boot from the procfs uptime file
// ("12345.67 54321.00": uptime, then idle time summed over CPUs). Like the
// kernel release, uptime is not namespaced (short of a time namespace,
// which Docker does not use), so the agent container's own /proc gives the
// host's value.
func CollectUptime(procFS fs.FS) (int64, error) {
	const p = "uptime"
	b, err := fs.ReadFile(procFS, p)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0, fmt.Errorf("%s is empty", p)
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || secs < 0 || secs > 100*365*24*3600 {
		return 0, fmt.Errorf("%s: implausible uptime %q", p, fields[0])
	}
	return int64(secs), nil
}
