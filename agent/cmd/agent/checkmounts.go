package main

import (
	"fmt"
	"io"
	"io/fs"
	"path"

	"github.com/pippinmole/upkeep.sh/agent/internal/target"
)

// checkMounts is `agent check-mounts`: a one-shot report of what the agent
// can see through its mounts, for users and for CI
// (.github/workflows/host-mount.yml). It needs no server or credentials:
//
//	docker compose run --rm upkeep-agent check-mounts
//
// It exits 1 when a host unix socket is reachable under the host root (the
// same check as the startup WARN and the host_mount collector), 0
// otherwise. Missing expected paths are reported but don't fail it: which
// ones apply depends on the host (dpkg only on Debian/Ubuntu).
func checkMounts(w io.Writer) int {
	l := localTarget()
	fmt.Fprintf(w, "host root: %s (run visible: %v)\n", l.HostRoot(), l.RunVisible())
	for _, p := range append([]string{"etc/os-release"}, target.ExtraPaths...) {
		state := "visible"
		if _, err := fs.Stat(l.FS(), p); err != nil {
			state = "NOT visible"
		}
		fmt.Fprintf(w, "  %-22s %s\n", p, state)
	}
	socks := l.ReachableSockets(dockerSocket())
	if len(socks) == 0 {
		fmt.Fprintln(w, "host sockets reachable under the host root: none")
		return 0
	}
	fmt.Fprintf(w, "FAIL: %s\n", l.SocketWarning(socks))
	for _, s := range socks {
		fmt.Fprintf(w, "  reachable: %s\n", path.Join(l.HostRoot(), s))
	}
	return 1
}
