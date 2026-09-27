package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CollectUptime reads whole seconds since boot from procRoot's uptime file
// ("12345.67 54321.00": uptime, then idle time summed over CPUs). Like the
// kernel release, uptime is not namespaced (short of a time namespace,
// which Docker does not use), so the agent container's own /proc gives the
// host's value.
func CollectUptime(procRoot string) (int64, error) {
	p := filepath.Join(procRoot, "uptime")
	b, err := os.ReadFile(p)
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
