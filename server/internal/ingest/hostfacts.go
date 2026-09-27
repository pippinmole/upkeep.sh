package ingest

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/pippinmole/upkeep.sh/server/internal/hostfacts"
)

// Server-side row caps per kind. The agent caps lower and flags
// truncation; these only bound what a misbehaving agent can store.
const (
	maxServiceRows  = 5000
	maxListenerRows = 5000
	maxUserRows     = 5000
	maxAttrsBytes   = 4096
)

// collectorStatusOK is the strict form of collectorOK for sections added
// after per-collector status existed: no collectors map means an agent
// that never sent the section, so it is never authoritative.
func collectorStatusOK(p SnapshotPayload, name string) bool {
	return p.Collectors != nil && p.Collectors[name].Status == CollectorStatusOK
}

func collectorTruncated(p SnapshotPayload, name string) bool {
	return p.Collectors != nil && p.Collectors[name].Truncated
}

// planFacts decides which host fact kinds this payload is authoritative
// for and builds one canonical set for each (the rule is the same as for
// package ecosystems: docs/PROTOCOL.md "collectors"):
//
//   - a kind is diffed iff its collector reported ok, even when its list is
//     empty or absent (ok and empty closes every open range);
//   - error / skipped / missing collector: the kind's ranges are left
//     exactly as they are;
//   - ok but truncated: the set is additive (opens and replaces rows,
//     never closes a missing one);
//   - payloads without a collectors map (older agents) are authoritative
//     for TCP listeners only, the one section those agents sent, since
//     they never pushed after a collector failure.
func planFacts(p SnapshotPayload) (sets []hostfacts.Set, skipped []string) {
	if collectorStatusOK(p, CollectorSystemdServices) {
		sets = append(sets, servicesSet(p))
	}

	legacy := p.Collectors == nil
	for _, tr := range []struct {
		transport, collector string
	}{{"tcp", CollectorTCPListeners}, {"udp", CollectorUDPListeners}} {
		ok := collectorStatusOK(p, tr.collector) || (legacy && tr.transport == "tcp")
		if !ok {
			continue
		}
		set, dropped := listenersSet(p, tr.transport, collectorTruncated(p, tr.collector))
		if dropped > 0 {
			skipped = append(skipped, fmt.Sprintf("listeners:%s: dropped %d invalid sockets", tr.transport, dropped))
		}
		sets = append(sets, set)
	}

	if collectorStatusOK(p, CollectorLocalUsers) {
		sets = append(sets, usersSet(p))
	}
	return sets, skipped
}

func nullText(s string, n int) any {
	if s = hostfacts.Clip(s, n); s == "" {
		return nil
	}
	return s
}

func servicesSet(p SnapshotPayload) hostfacts.Set {
	var rows []hostfacts.Row
	additive := collectorTruncated(p, CollectorSystemdServices)
	for _, s := range p.Services {
		name := hostfacts.Clip(s.Name, 256)
		if s.Manager != "systemd" || name == "" {
			continue
		}
		if len(rows) == maxServiceRows {
			additive = true
			break
		}
		rows = append(rows, hostfacts.Row{
			Key: "systemd/" + name,
			Values: []any{"systemd", name,
				nullText(s.DisplayName, 512), nullText(s.StartMode, 32), nullText(s.State, 32),
				nullText(s.RunAs, 64), nullText(s.BinaryPath, 1024), sanitizeAttrs(s.Attrs)},
		})
	}
	return hostfacts.NewSet("services:systemd", hostfacts.ServicesTable, "systemd", rows, additive)
}

// sanitizeAttrs returns attrs if it re-encodes as JSON Postgres' jsonb can
// hold (no \u0000) within maxAttrsBytes, else an empty object.
func sanitizeAttrs(attrs map[string]any) map[string]any {
	if len(attrs) == 0 {
		return map[string]any{}
	}
	b, err := json.Marshal(attrs)
	if err != nil || len(b) > maxAttrsBytes || strings.Contains(string(b), `\u0000`) {
		return map[string]any{}
	}
	return attrs
}

// listenersSet builds the set for one transport from listening_sockets:
// proto must be the transport or its "6" variant, the port 1-65535 and the
// address a valid IP. dropped counts the sockets rejected.
func listenersSet(p SnapshotPayload, transport string, additive bool) (hostfacts.Set, int) {
	var rows []hostfacts.Row
	dropped := 0
	for _, s := range p.ListeningSockets {
		if s.Proto != transport && s.Proto != transport+"6" {
			continue
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(s.LocalAddr))
		if err != nil || addr.Zone() != "" || s.Port < 1 || s.Port > 65535 {
			dropped++
			continue
		}
		if len(rows) == maxListenerRows {
			additive = true
			break
		}
		a := addr.String()
		rows = append(rows, hostfacts.Row{
			Key:    s.Proto + " " + net.JoinHostPort(a, strconv.Itoa(s.Port)),
			Values: []any{transport, s.Proto, a, s.Port, nullText(s.ProcessName, 64)},
		})
	}
	return hostfacts.NewSet("listeners:"+transport, hostfacts.ListenersTable, transport, rows, additive), dropped
}

func usersSet(p SnapshotPayload) hostfacts.Set {
	var rows []hostfacts.Row
	additive := collectorTruncated(p, CollectorLocalUsers)
	for _, u := range p.Users {
		name := hostfacts.Clip(u.Name, 64)
		if name == "" || u.UID < 0 || u.GID < 0 {
			continue
		}
		if len(rows) == maxUserRows {
			additive = true
			break
		}
		groups := []string{}
		for _, g := range u.Groups {
			if g = hostfacts.Clip(g, 64); g != "" && len(groups) < 256 {
				groups = append(groups, g)
			}
		}
		rows = append(rows, hostfacts.Row{
			Key: name,
			Values: []any{name, u.UID, u.GID, nullText(u.Home, 256), nullText(u.Shell, 256),
				groups, u.LoginShell, u.Admin || u.UID == 0},
		})
	}
	return hostfacts.NewSet("users:local", hostfacts.UsersTable, "", rows, additive)
}

// uptimeSeconds returns the reported uptime when the uptime collector
// succeeded and the value is plausible (under a century).
func uptimeSeconds(p SnapshotPayload) *int64 {
	if !collectorStatusOK(p, CollectorUptime) || p.UptimeSeconds == nil {
		return nil
	}
	if v := *p.UptimeSeconds; v < 0 || v > 100*365*24*3600 {
		return nil
	}
	return p.UptimeSeconds
}

// hostArch returns os.arch when the arch collector succeeded and the value
// looks like an architecture name ("amd64", "arm64", "ppc64el").
func hostArch(p SnapshotPayload) string {
	a := strings.TrimSpace(p.OS.Arch)
	if !collectorStatusOK(p, CollectorArch) || a == "" || len(a) > 32 {
		return ""
	}
	for _, r := range a {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return ""
		}
	}
	return a
}

// linuxFacts validates the facts block for a Linux host (the only family
// with facts so far); anything else stores '{}'.
func linuxFacts(p SnapshotPayload, family string) ([]byte, error) {
	if family != "linux" {
		return []byte("{}"), nil
	}
	b, _, err := hostfacts.ValidateLinuxFacts(p.Facts,
		collectorStatusOK(p, CollectorDeletedLibs), collectorStatusOK(p, CollectorUnattendedUpgrades))
	return b, err
}
