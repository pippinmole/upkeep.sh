// Package target models a host the agent collects facts from, and how it
// reaches that host (its collection mode).
//
// Every agent has the machine it runs on ("local" mode), whose filesystem
// is visible read-only under a host root (/host in the Docker deployment),
// and may have remote hosts added in the dashboard ("ssh" mode, ssh.go),
// whose filesystem it reads over read-only SFTP. Collectors take a Target
// and ask it for what they need; they never hardcode /host paths.
//
// WinRM (Windows) is reserved and not implemented (DOMAIN_MODEL.md §4.2).
package target

import (
	"io/fs"
	"os"
	"path"
	"strings"
)

// Mode is how the agent reaches a target. Values match agent_hosts.mode in
// the planned schema (DOMAIN_MODEL.md §4.6).
type Mode string

const (
	// ModeLocal: the agent runs on the target and reads its files directly.
	ModeLocal Mode = "local"

	// ModeSSH: a remote host read over SFTP (SSH). ModeWinRM is reserved.
	ModeSSH   Mode = "ssh"
	ModeWinRM Mode = "winrm"
)

// LocalRef is the target ref of the agent's own host. It is what the
// payload's host.ref carries, and what the server maps a legacy payload
// without a host block to.
const LocalRef = "local"

// Target is one host the agent collects from.
type Target interface {
	// Ref names the target within this agent: LocalRef for the agent's own
	// host, later the remote target name assigned in the dashboard.
	Ref() string
	Mode() Mode
	// FS is a read-only view of the target's filesystem rooted at its "/".
	// Paths are fs.FS style: slash-separated, no leading slash
	// ("etc/os-release"). OS detection and file-based collectors read
	// through this, which is also what lets tests point them at a fixture
	// directory instead of the real machine.
	FS() fs.FS
}

// LiveProc is an optional capability: the target's live kernel state
// (procfs) is readable by the agent at ProcRoot. Only a local Linux target
// running with the host's PID and network namespaces (pid: host,
// network_mode: host) has this; its native /proc then describes the host,
// not the agent's container. Collectors needing live process/socket state
// type-assert for it and report "skipped" when a target lacks it.
//
// Future platform-specific capabilities (e.g. a Windows registry reader)
// follow the same pattern: a small interface here, implemented only by the
// targets that can provide it.
type LiveProc interface {
	ProcRoot() string
}

// ProcFiles is an optional capability: the target's procfs is readable
// file by file, as an fs.FS rooted at its /proc. That is enough for
// single-file kernel facts (running kernel, uptime, arch), and a remote
// target has it; walking every process (listeners, deleted libraries)
// still needs LiveProc.
type ProcFiles interface {
	ProcFS() fs.FS
}

// Local is the agent's own host.
type Local struct {
	fsys      fs.FS
	hostRoot  string
	extraRoot string
	withExtra bool // built by NewLocalWithExtra (the Docker deployment)
	procRoot  string
}

// NewLocal returns the local target whose filesystem is visible at
// hostRoot (e.g. "/host" in the container, "/" for a bare-metal install)
// and whose live procfs is at procRoot (normally "/proc"). An empty
// procRoot means live process state is not available.
//
// Caveat of reading a host filesystem through a bind mount: an *absolute*
// symlink on the host (e.g. /var/run -> /run) resolves against the agent
// container's root, not hostRoot. Collectors therefore read canonical
// paths (run/..., not var/run/...) rather than rely on host symlinks.
func NewLocal(hostRoot, procRoot string) *Local {
	return &Local{fsys: os.DirFS(hostRoot), hostRoot: hostRoot, procRoot: procRoot}
}

// NewLocalWithExtra is NewLocal for the Docker deployment: the host's /
// bound non-recursively at hostRoot, plus ExtraPaths bound under
// extraRoot (see hostmounts.go). Paths missing from extraRoot fall back to
// hostRoot, so an older compose file without the extra binds still works
// wherever those directories sit on the root filesystem.
func NewLocalWithExtra(hostRoot, extraRoot, procRoot string) *Local {
	return &Local{fsys: newHostFS(hostRoot, extraRoot), hostRoot: hostRoot, extraRoot: extraRoot, withExtra: true, procRoot: procRoot}
}

// RunVisible reports whether the host's /run (a tmpfs, holding e.g.
// /run/reboot-required) is visible under the host root. With NewLocal
// (bare metal, fixtures) it is taken as visible. With NewLocalWithExtra
// (the Docker deployment) it is visible only if <hostRoot>/run is a
// different filesystem than <hostRoot>: under the non-recursive bind it
// is just the mountpoint directory on the root filesystem, which can
// hold stale leftovers (Ubuntu's cloud image has run/needrestart there),
// so its contents mean nothing.
func (l *Local) RunVisible() bool {
	if !l.withExtra {
		return true
	}
	return !sameDevice(l.hostRoot, path.Join(l.hostRoot, "run"))
}

// HostRoot is where the host's / is visible ("/" on bare metal).
func (l *Local) HostRoot() string { return l.hostRoot }

// BareMetal reports whether the agent runs directly on the host (host
// root "/"), where every host path is visible as is.
func (l *Local) BareMetal() bool { return l.hostRoot == "/" }

// MissingHint explains a path that every host of its kind has but that
// isn't visible: in a container that means the agent's mounts. On bare
// metal the path is genuinely missing, so there is no hint.
func (l *Local) MissingHint(name string) string {
	if l.hostRoot == "" || l.BareMetal() {
		return ""
	}
	where := l.hostRoot
	if l.extraRoot != "" {
		for _, p := range ExtraPaths {
			if name == p || strings.HasPrefix(name, p+"/") {
				where += " or " + path.Join(l.extraRoot, p)
				break
			}
		}
	}
	return name + " not visible under " + where + "; check the agent's mounts (agent/docker-compose.example.yml)"
}

func (l *Local) Ref() string      { return LocalRef }
func (l *Local) Mode() Mode       { return ModeLocal }
func (l *Local) FS() fs.FS        { return l.fsys }
func (l *Local) ProcRoot() string { return l.procRoot }

// ProcFS is the live procfs as an fs.FS (nil without one).
func (l *Local) ProcFS() fs.FS {
	if l.procRoot == "" {
		return nil
	}
	return os.DirFS(l.procRoot)
}

// ProcFSOf returns the target's procfs files and whether it has them.
func ProcFSOf(t Target) (fs.FS, bool) {
	p, ok := t.(ProcFiles)
	if !ok {
		return nil, false
	}
	fsys := p.ProcFS()
	return fsys, fsys != nil
}

// ProcRootOf returns the target's procfs root and whether it has one.
func ProcRootOf(t Target) (string, bool) {
	p, ok := t.(LiveProc)
	if !ok || p.ProcRoot() == "" {
		return "", false
	}
	return p.ProcRoot(), true
}
