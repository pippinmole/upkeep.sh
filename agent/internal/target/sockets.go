package target

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// knownSockets are host control sockets that must never be reachable
// under the host root: each one is root (or close to it) on the host for
// anything that can connect(), and a read-only mount doesn't stop
// connect(). "*" matches one path element (run/user/<uid>/...).
var knownSockets = []string{
	"run/docker.sock",
	"var/run/docker.sock",
	"run/containerd/containerd.sock",
	"run/podman/podman.sock",
	"run/user/*/docker.sock",
	"run/user/*/podman/podman.sock",
	"run/systemd/private",
	"run/dbus/system_bus_socket",
	"run/snapd.socket",
	"run/crio/crio.sock",
	"run/k3s/containerd/containerd.sock",
	"var/snap/lxd/common/lxd/unix.socket",
	"var/lib/lxd/unix.socket",
	"var/lib/incus/unix.socket",
	"var/snap/microk8s/common/run/containerd.sock",
}

// Limits for the walk of run/: deep enough for run/user/<uid>/bus and
// run/containerd/s/<id>, bounded so a huge /run can't stall startup.
const (
	socketWalkDepth   = 4
	socketWalkEntries = 20000
)

// ReachableSockets lists unix sockets of the host that the agent can
// reach under its host root, as host paths relative to "/" (sorted,
// deduplicated). With the non-recursive / bind of the compose example
// the list is empty: every socket in /run sits on a tmpfs, a nested mount
// the bind doesn't carry. A non-empty list means the host mount is
// recursive (the old "/:/host:ro"), or the engine ignored
// bind-recursive=disabled, or a socket sits on the root filesystem itself.
//
// optIn is the Docker socket path the agent was deliberately given
// (SW_DOCKER_SOCKET, a container path); it is not reported. Bare metal
// (host root "/") returns nil: the agent then runs as a host process and
// the check means nothing.
func (l *Local) ReachableSockets(optIn string) []string {
	if l.hostRoot == "" || l.BareMetal() {
		return nil
	}
	root := l.hostRoot
	skip := ""
	if rel, ok := strings.CutPrefix(filepath.Clean(optIn), filepath.Clean(root)+"/"); ok {
		skip = rel
	}

	found := map[string]bool{}
	add := func(rel string) {
		// Resolve host symlinks against the host root (var/run -> /run is
		// absolute and would otherwise escape into the container), so
		// run/docker.sock and var/run/docker.sock count once, and never
		// match the container's own /var/run/docker.sock (the opt-in).
		real, ok := resolveUnder(root, rel)
		if !ok || real == skip {
			return
		}
		fi, err := os.Lstat(filepath.Join(root, real))
		if err == nil && fi.Mode().Type() == fs.ModeSocket {
			found[real] = true
		}
	}

	for _, pat := range knownSockets {
		if !strings.Contains(pat, "*") {
			add(pat)
			continue
		}
		matches, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(pat)))
		for _, m := range matches {
			if rel, err := filepath.Rel(root, m); err == nil {
				add(filepath.ToSlash(rel))
			}
		}
	}

	// Anything else socket-shaped in run/ (the walk doesn't follow
	// symlinks; sockets elsewhere on the host are covered by the list).
	n := 0
	runDir := filepath.Join(root, "run")
	_ = filepath.WalkDir(runDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if n++; n > socketWalkEntries {
			return filepath.SkipAll
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() && strings.Count(rel, "/") >= socketWalkDepth {
			return filepath.SkipDir
		}
		if d.Type() == fs.ModeSocket && rel != skip {
			found[rel] = true
		}
		return nil
	})

	out := make([]string, 0, len(found))
	for p := range found {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// resolveUnder resolves rel (slash-separated, relative to the host's /)
// component by component, following symlinks as the host would: an
// absolute target restarts at root, a relative one at its directory. It
// returns the resolved host path relative to root, and false when a
// component is missing or the links loop.
func resolveUnder(root, rel string) (string, bool) {
	parts := strings.Split(path.Clean(rel), "/")
	var cur []string
	for hops := 0; len(parts) > 0; {
		name := parts[0]
		parts = parts[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			if len(cur) > 0 {
				cur = cur[:len(cur)-1]
			}
			continue
		}
		next := append(slices.Clone(cur), name)
		p := filepath.Join(root, filepath.FromSlash(strings.Join(next, "/")))
		fi, err := os.Lstat(p)
		if err != nil {
			return "", false
		}
		if fi.Mode().Type() != fs.ModeSymlink {
			cur = next
			continue
		}
		if hops++; hops > 40 {
			return "", false
		}
		target, err := os.Readlink(p)
		if err != nil {
			return "", false
		}
		if strings.HasPrefix(target, "/") {
			cur = nil
		}
		parts = append(strings.Split(strings.TrimPrefix(target, "/"), "/"), parts...)
	}
	return strings.Join(cur, "/"), true
}
