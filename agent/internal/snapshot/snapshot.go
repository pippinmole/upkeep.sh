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
	"time"

	"github.com/pippinmole/upkeep.sh/agent/internal/collector"
	"github.com/pippinmole/upkeep.sh/agent/internal/collector/pkgsource"
	"github.com/pippinmole/upkeep.sh/agent/internal/detect"
	"github.com/pippinmole/upkeep.sh/agent/internal/target"
)

type Collector struct {
	Sources *pkgsource.Registry

	// PublicIPs looks up the agent's public addresses. It is a field so
	// tests can stub out the network; nil skips the lookup.
	PublicIPs func(context.Context) (ipv4, ipv6 string)

	// Now defaults to time.Now.
	Now func() time.Time

	// Agent, if set, is sent as the snapshot's agent block.
	Agent *collector.Agent
}

// New returns a Collector with the production package sources and public
// IP lookup.
func New() *Collector {
	return &Collector{Sources: pkgsource.Default(), PublicIPs: collector.CollectPublicIPs}
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

	// Live kernel state needs the target's procfs (see target.LiveProc).
	procRoot, hasProc := target.ProcRootOf(t)

	// Running kernel: the server raises kernel CVEs only against the
	// kernel actually running (DOMAIN_MODEL.md Q7).
	switch {
	case !isLinux:
		status[collector.CollectorKernel] = notLinux
	case !hasProc:
		status[collector.CollectorKernel] = collector.Skipped("target has no readable procfs")
	default:
		rel, err := collector.CollectKernelRelease(procRoot)
		snap.OS.Kernel = rel
		status[collector.CollectorKernel] = result(err)
	}

	noProc := collector.Skipped("target has no readable procfs")

	switch {
	case !isLinux:
		status[collector.CollectorUptime] = notLinux
	case !hasProc:
		status[collector.CollectorUptime] = noProc
	default:
		up, err := collector.CollectUptime(procRoot)
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
		arch, err := collector.CollectArch(debPkgs, procRoot)
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
			status[collector.CollectorLocalUsers] = collector.Failed(err)
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
		status[collector.CollectorUnattendedUpgrades] = result(err)
	} else {
		status[collector.CollectorUnattendedUpgrades] = collector.Skipped("apt is Debian/Ubuntu only")
	}
	if facts.NeedsRestart != nil || facts.UnattendedUpgrades != nil {
		snap.Facts = facts
	}

	// The reboot-required flag file is a Debian/Ubuntu convention; its
	// absence elsewhere would read as a false "no reboot pending".
	if isLinux && osInfo.Like("debian", "ubuntu") {
		req, pkgs, err := collector.CollectRebootRequired(t.FS())
		snap.RebootRequired, snap.RebootPackages = req, pkgs
		status[collector.CollectorRebootRequired] = result(err)
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

	return snap
}

func result(err error) collector.CollectorStatus {
	if err != nil {
		return collector.Failed(err)
	}
	return collector.OK()
}
