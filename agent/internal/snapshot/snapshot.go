// Package snapshot assembles one Snapshot for one target: detect what the
// target is, then run each collector that applies to it, recording every
// collector's outcome in Snapshot.Collectors.
//
// Collection never fails as a whole. A collector error becomes a status
// entry and leaves its section empty, so the rest of the snapshot still
// reaches the server, and the server can tell "failed" from "empty".
package snapshot

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/pippinmole/upkeep.sh/agent/internal/collector"
	"github.com/pippinmole/upkeep.sh/agent/internal/collector/pkgsource"
	"github.com/pippinmole/upkeep.sh/agent/internal/detect"
	"github.com/pippinmole/upkeep.sh/agent/internal/dockerapi"
	"github.com/pippinmole/upkeep.sh/agent/internal/target"
)

type Collector struct {
	Sources *pkgsource.Registry

	// PublicIPs looks up the agent's public addresses. It is a field so
	// tests can stub out the network; nil skips the lookup.
	PublicIPs func(context.Context) (ipv4, ipv6 string)

	// DockerSocket is the Docker Engine socket (SW_DOCKER_SOCKET). It is
	// only ever opened for the local target; empty disables Docker
	// collection (reported like an unmounted socket).
	DockerSocket string
	// OpenDocker connects to the engine at a socket path: dockerapi.Open
	// in production, a stub in tests. nil disables Docker collection.
	OpenDocker func(ctx context.Context, socket string) (dockerapi.Client, error)

	// Now defaults to time.Now.
	Now func() time.Time

	// Agent, if set, is sent as the snapshot's agent block.
	Agent *collector.Agent
}

// New returns a Collector with the production package sources, public IP
// lookup and Docker opener, using the default Docker socket.
func New() *Collector {
	return &Collector{
		Sources:      pkgsource.Default(),
		PublicIPs:    collector.CollectPublicIPs,
		DockerSocket: dockerapi.DefaultSocket,
		OpenDocker:   openDocker,
	}
}

// openDocker adapts dockerapi.Open to Collector.OpenDocker. It must not
// return a typed nil *Engine inside the interface.
func openDocker(ctx context.Context, socket string) (dockerapi.Client, error) {
	e, err := dockerapi.Open(ctx, socket)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// Collect gathers one snapshot of t.
func (c *Collector) Collect(ctx context.Context, t target.Target) collector.Snapshot {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	snap := collector.Snapshot{
		SchemaVersion: collector.SchemaVersion,
		CollectedAt:   now().UTC().Format(time.RFC3339),
		Agent:         c.Agent,
		Host:          collector.Host{Ref: t.Ref()},
		Collectors:    map[string]collector.CollectorStatus{},
	}
	status := snap.Collectors

	osInfo, err := detect.Detect(t.FS())
	if err != nil {
		status[collector.CollectorOS] = collector.Failed(err)
	} else {
		status[collector.CollectorOS] = collector.OK()
	}
	snap.Host.OSFamily = string(osInfo.Family)
	snap.OS = collector.OSRelease{ID: osInfo.ID, VersionID: osInfo.VersionID, Codename: osInfo.Codename}

	isLinux := osInfo.Family == detect.FamilyLinux
	notLinux := collector.Skipped(fmt.Sprintf("not implemented for OS family %q", osInfo.Family))

	// Identity. Windows (MachineGuid) and macOS (IOPlatformUUID) plug in
	// here once those families have collectors.
	if isLinux {
		id, err := detect.LinuxIdentity(t.FS())
		snap.Host.Hostname = id.Hostname
		snap.Host.Identity.MachineID = id.MachineID
		status[collector.CollectorHostIdentity] = result(err)
	} else {
		status[collector.CollectorHostIdentity] = notLinux
	}

	pkgs, pkgStatus := c.Sources.Collect(ctx, t, osInfo)
	snap.Packages = pkgs
	for name, st := range pkgStatus {
		status[name] = st
	}

	// Single-file kernel facts need the target's procfs files
	// (target.ProcFiles, local or remote); walking live process state
	// needs the local procfs (target.LiveProc).
	procFS, hasProcFiles := target.ProcFSOf(t)
	procRoot, hasProc := target.ProcRootOf(t)

	// Running kernel: the server raises kernel CVEs only against the
	// kernel actually running (DOMAIN_MODEL.md Q7).
	switch {
	case !isLinux:
		status[collector.CollectorKernel] = notLinux
	case !hasProcFiles:
		status[collector.CollectorKernel] = collector.Skipped("target has no readable procfs")
	default:
		rel, err := collector.CollectKernelRelease(procFS)
		snap.OS.Kernel = rel
		status[collector.CollectorKernel] = result(err)
	}

	noProc := collector.Skipped("target has no readable procfs")

	switch {
	case !isLinux:
		status[collector.CollectorUptime] = notLinux
	case !hasProcFiles:
		status[collector.CollectorUptime] = noProc
	default:
		up, err := collector.CollectUptime(procFS)
		if err == nil {
			snap.UptimeSeconds = &up
		}
		status[collector.CollectorUptime] = result(err)
	}

	// Architecture prefers dpkg's native arch from the inventory just
	// collected (see CollectArch), so pass packages only when dpkg's
	// source succeeded.
	var debPkgs []collector.Package
	if pkgStatus["deb_packages"].Status == collector.StatusOK {
		debPkgs = pkgs
	}
	if isLinux {
		arch, err := collector.CollectArch(debPkgs, procFS)
		snap.OS.Arch = arch
		status[collector.CollectorArch] = result(err)
	} else {
		status[collector.CollectorArch] = notLinux
	}

	listenerCollectors := map[collector.Transport]string{
		collector.TransportTCP: collector.CollectorTCPListeners,
		collector.TransportUDP: collector.CollectorUDPListeners,
	}
	switch {
	case !isLinux:
		for _, name := range listenerCollectors {
			status[name] = notLinux
		}
	case !hasProc:
		for _, name := range listenerCollectors {
			status[name] = noProc
		}
	default:
		results := collector.CollectListeners(procRoot)
		for _, tr := range []collector.Transport{collector.TransportTCP, collector.TransportUDP} {
			r := results[tr]
			if r.Err != nil {
				status[listenerCollectors[tr]] = collector.Failed(r.Err)
				continue
			}
			snap.ListeningSockets = append(snap.ListeningSockets, r.Sockets...)
			status[listenerCollectors[tr]] = collector.OKTruncated(r.Truncated)
		}
	}

	// Which systemd service each process runs under: service running
	// state, and the unit to restart for a process on deleted libraries.
	var units map[int]string
	if isLinux && hasProc {
		units = collector.ProcessUnits(procRoot)
	}

	if isLinux {
		svcs, truncated, err := collector.CollectSystemdServices(t.FS(), units)
		switch {
		case errors.Is(err, collector.ErrNoSystemd) && pid1IsSystemd(procFS, hasProcFiles):
			// The host runs systemd, so its unit directories exist: the
			// agent just can't see them.
			status[collector.CollectorSystemdServices] = collector.Failed(target.NotVisible(t,
				&fs.PathError{Op: "readdir", Path: "etc/systemd/system", Err: fs.ErrNotExist}))
		case errors.Is(err, collector.ErrNoSystemd):
			status[collector.CollectorSystemdServices] = collector.Skipped(err.Error())
		case err != nil:
			status[collector.CollectorSystemdServices] = collector.Failed(err)
		default:
			snap.Services = svcs
			status[collector.CollectorSystemdServices] = collector.OKTruncated(truncated)
		}

		users, truncated, err := collector.CollectLocalUsers(t.FS())
		if err != nil {
			status[collector.CollectorLocalUsers] = collector.Failed(target.NotVisible(t, err))
		} else {
			snap.Users = users
			status[collector.CollectorLocalUsers] = collector.OKTruncated(truncated)
		}
	} else {
		status[collector.CollectorSystemdServices] = notLinux
		status[collector.CollectorLocalUsers] = notLinux
	}

	facts := &collector.Facts{}
	switch {
	case !isLinux:
		status[collector.CollectorDeletedLibs] = notLinux
	case !hasProc:
		status[collector.CollectorDeletedLibs] = noProc
	default:
		nr, err := collector.CollectDeletedLibs(procRoot, units)
		if err == nil {
			facts.NeedsRestart = &nr
			status[collector.CollectorDeletedLibs] = collector.OKTruncated(nr.Truncated)
		} else {
			status[collector.CollectorDeletedLibs] = collector.Failed(err)
		}
	}
	if isLinux && osInfo.Like("debian", "ubuntu") {
		uu, err := collector.CollectUnattendedUpgrades(t.FS(), debPkgs)
		if err == nil {
			facts.UnattendedUpgrades = &uu
		}
		status[collector.CollectorUnattendedUpgrades] = result(target.NotVisible(t, err))
	} else {
		status[collector.CollectorUnattendedUpgrades] = collector.Skipped("apt is Debian/Ubuntu only")
	}
	if facts.NeedsRestart != nil || facts.UnattendedUpgrades != nil {
		snap.Facts = facts
	}

	// The reboot-required flag file is a Debian/Ubuntu convention; its
	// absence elsewhere would read as a false "no reboot pending".
	if isLinux && osInfo.Like("debian", "ubuntu") {
		// Without the host's /run (the Docker deployment doesn't mount it)
		// this is derived from the running kernel vs dpkg's kernels.
		r, err := collector.CollectRebootRequired(t.FS(), snap.OS.Kernel, debPkgs)
		switch {
		case errors.Is(err, collector.ErrRebootUnknown):
			// Unknown, not "no reboot pending".
			status[collector.CollectorRebootRequired] = collector.Skipped(err.Error())
		case err != nil:
			status[collector.CollectorRebootRequired] = collector.Failed(err)
		default:
			snap.RebootRequired, snap.RebootPackages, snap.RebootSource = r.Required, r.Packages, r.Source
			status[collector.CollectorRebootRequired] = collector.OK()
		}
	} else {
		status[collector.CollectorRebootRequired] = collector.Skipped("no pending-reboot source for this OS")
	}

	// The public IP lookup runs from the agent's own network, so it only
	// describes the target when the target is the agent's own host.
	switch {
	case t.Mode() != target.ModeLocal:
		status[collector.CollectorPublicIP] = collector.Skipped("only meaningful for the local host")
	case c.PublicIPs == nil:
		status[collector.CollectorPublicIP] = collector.Skipped("disabled")
	default:
		// Best-effort by design: empty results are normal and still "ok".
		ipCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		snap.PublicIPv4, snap.PublicIPv6 = c.PublicIPs(ipCtx)
		cancel()
		status[collector.CollectorPublicIP] = collector.OK()
	}

	snap.Docker = c.collectDocker(ctx, t, isLinux, notLinux, status)

	status[collector.CollectorHostMount] = c.hostMountStatus(t)

	return snap
}

// hostMountStatus reports host sockets reachable under the local target's
// host root: the host mount must not carry them (docker-compose.example.yml).
func (c *Collector) hostMountStatus(t target.Target) collector.CollectorStatus {
	l, ok := t.(*target.Local)
	switch {
	case !ok || t.Mode() != target.ModeLocal:
		return collector.Skipped("only meaningful for the local host")
	case l.BareMetal():
		return collector.Skipped("agent runs on the host (SW_HOST_ROOT=/)")
	}
	if socks := l.ReachableSockets(c.DockerSocket); len(socks) > 0 {
		return collector.Failed(errors.New(l.SocketWarning(socks)))
	}
	return collector.OK()
}

// pid1IsSystemd reports whether the target's PID 1 is systemd, from its
// procfs (false when there is none).
func pid1IsSystemd(procFS fs.FS, ok bool) bool {
	if !ok {
		return false
	}
	b, err := fs.ReadFile(procFS, "1/comm")
	return err == nil && strings.TrimSpace(string(b)) == "systemd"
}

func result(err error) collector.CollectorStatus {
	if err != nil {
		return collector.Failed(err)
	}
	return collector.OK()
}
