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

	switch {
	case !isLinux:
		status[collector.CollectorTCPListeners] = notLinux
	case !hasProc:
		status[collector.CollectorTCPListeners] = collector.Skipped("target has no readable procfs")
	default:
		socks, err := collector.CollectListeningSockets(procRoot)
		snap.ListeningSockets = socks
		status[collector.CollectorTCPListeners] = result(err)
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
