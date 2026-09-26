// Package target models a host the agent collects facts from, and how it
// reaches that host (its collection mode).
//
// Today every agent has exactly one target: the machine it runs on
// ("local" mode), whose filesystem is visible read-only under a host root
// (/host in the Docker deployment). The abstraction exists so that one
// agent can later collect several hosts of different kinds (e.g. two
// Windows VMs and a Debian box from one subnet agent) without restructuring
// the collectors: collectors take a Target and ask it for what they need,
// they never hardcode /host paths.
//
// Remote modes (ssh, winrm; DOMAIN_MODEL.md §4.2) are deliberately not
// implemented. They require executing commands on the remote machine and
// holding credentials for it, both of which are open product decisions
// (DOMAIN_MODEL.md §6 Q3/Q4). When they are decided, a remote target is a
// new type implementing Target (e.g. FS backed by read-only SFTP), plus any
// capability interfaces below that it can honour.
package target

import (
	"io/fs"
	"os"
)

// Mode is how the agent reaches a target. Values match agent_hosts.mode in
// the planned schema (DOMAIN_MODEL.md §4.6).
type Mode string

const (
	// ModeLocal: the agent runs on the target and reads its files directly.
	ModeLocal Mode = "local"

	// ModeSSH and ModeWinRM are reserved for remote collection. No Target
	// implements them yet; see the package comment.
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

// Local is the agent's own host.
type Local struct {
	fsys     fs.FS
	procRoot string
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
	return &Local{fsys: os.DirFS(hostRoot), procRoot: procRoot}
}

func (l *Local) Ref() string      { return LocalRef }
func (l *Local) Mode() Mode       { return ModeLocal }
func (l *Local) FS() fs.FS        { return l.fsys }
func (l *Local) ProcRoot() string { return l.procRoot }

// ProcRootOf returns the target's procfs root and whether it has one.
func ProcRootOf(t Target) (string, bool) {
	p, ok := t.(LiveProc)
	if !ok || p.ProcRoot() == "" {
		return "", false
	}
	return p.ProcRoot(), true
}
