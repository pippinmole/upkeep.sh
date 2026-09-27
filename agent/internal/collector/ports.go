package collector

import (
	"bufio"
	"cmp"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Transport names a listener family; each is its own collector
// (tcp_listeners, udp_listeners) and succeeds or fails on its own.
type Transport string

const (
	TransportTCP Transport = "tcp"
	TransportUDP Transport = "udp"
)

// ListenerResult is one transport's outcome from CollectListeners.
type ListenerResult struct {
	Sockets   []Socket
	Truncated bool
	Err       error
}

// CollectListeners reads /proc/net/{tcp,tcp6,udp,udp6} and maps each
// listening socket to its owning process by scanning /proc/<pid>/fd for
// its socket inode (one fd scan shared by both transports). It relies on
// the agent sharing the host's PID and network namespaces (pid: host,
// network_mode: host) so that /proc describes the host, not the container.
//
// What counts as listening:
//   - TCP: state LISTEN (0A).
//   - UDP has no listen state. A socket counts when it is bound to a
//     local port and unconnected: state 07 (TCP_CLOSE, the kernel's value
//     for an unconnected UDP socket) and an all-zero remote address and
//     port. A connected UDP socket (state 01, remote address set; e.g. a
//     DNS client) only accepts datagrams from its peer, so it is not a
//     listener.
//
// Sockets are deduplicated on (proto, address, port): SO_REUSEPORT lets
// several sockets (often several processes) share one, and the server's
// per-snapshot table is keyed that way. The first socket with a known
// owner wins. Results are sorted by (proto, port, address) and capped at
// MaxListenersPerTransport.
func CollectListeners(procRoot string) map[Transport]ListenerResult {
	out := map[Transport]ListenerResult{}
	for _, tr := range []Transport{TransportTCP, TransportUDP} {
		var res ListenerResult
		for _, proto := range []string{string(tr), string(tr) + "6"} {
			entries, err := parseProcNet(filepath.Join(procRoot, "net", proto), tr)
			if err != nil {
				if os.IsNotExist(err) {
					continue // e.g. IPv6 disabled
				}
				res.Err = err
				break
			}
			for i := range entries {
				entries[i].Proto = proto
			}
			res.Sockets = append(res.Sockets, entries...)
		}
		if res.Err != nil {
			res.Sockets = nil
		}
		out[tr] = res
	}

	inodeToPID := buildInodeToPIDMap(procRoot)
	names := map[int]string{}
	for tr, res := range out {
		for i, s := range res.Sockets {
			if pid, ok := inodeToPID[s.inode]; ok {
				res.Sockets[i].PID = pid
				if _, ok := names[pid]; !ok {
					names[pid] = processName(procRoot, pid)
				}
				res.Sockets[i].ProcessName = names[pid]
			}
		}
		res.Sockets = dedupeSockets(res.Sockets)
		if len(res.Sockets) > MaxListenersPerTransport {
			res.Sockets, res.Truncated = res.Sockets[:MaxListenersPerTransport], true
		}
		out[tr] = res
	}
	return out
}

// dedupeSockets sorts by (proto, port, address, has-no-owner, pid) and
// keeps the first of each (proto, address, port).
func dedupeSockets(socks []Socket) []Socket {
	slices.SortFunc(socks, func(a, b Socket) int {
		if c := cmp.Compare(a.Proto, b.Proto); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Port, b.Port); c != 0 {
			return c
		}
		if c := cmp.Compare(a.LocalAddr, b.LocalAddr); c != 0 {
			return c
		}
		if c := cmp.Compare(boolInt(a.PID == 0), boolInt(b.PID == 0)); c != 0 {
			return c
		}
		return cmp.Compare(a.PID, b.PID)
	})
	return slices.CompactFunc(socks, func(a, b Socket) bool {
		return a.Proto == b.Proto && a.LocalAddr == b.LocalAddr && a.Port == b.Port
	})
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// parseProcNet parses the listening rows of one /proc/net/{tcp,udp}{,6}
// file (see CollectListeners for the rules per transport). The inode is
// carried on the returned struct via an unexported field used only to
// build the pid map; it never reaches the JSON payload.
func parseProcNet(path string, tr Transport) ([]Socket, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Socket
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		local, remote, state := fields[1], fields[2], fields[3]
		switch tr {
		case TransportTCP:
			if state != "0A" { // TCP_LISTEN
				continue
			}
		case TransportUDP:
			if state != "07" || !zeroEndpoint(remote) { // unconnected
				continue
			}
		}
		addrHex, portHex, ok := strings.Cut(local, ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseInt(portHex, 16, 32)
		if err != nil || port == 0 {
			continue
		}
		ino, _ := strconv.Atoi(fields[9])
		out = append(out, Socket{
			LocalAddr: hexToIP(addrHex),
			Port:      int(port),
			inode:     ino,
		})
	}
	return out, sc.Err()
}

// zeroEndpoint reports whether a /proc/net "ADDR:PORT" hex endpoint is the
// all-zero address with port 0 (no peer).
func zeroEndpoint(ep string) bool {
	return strings.Trim(ep, "0:") == ""
}

func buildInodeToPIDMap(procRoot string) map[int]int {
	m := map[int]int{}
	for _, pid := range listPIDs(procRoot) {
		fdDir := filepath.Join(procRoot, strconv.Itoa(pid), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			var inode int
			if _, err := fmt.Sscanf(link, "socket:[%d]", &inode); err == nil {
				if _, seen := m[inode]; !seen {
					m[inode] = pid
				}
			}
		}
	}
	return m
}

// listPIDs returns the numeric entries of procRoot in ascending order.
func listPIDs(procRoot string) []int {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	var pids []int
	for _, d := range entries {
		if pid, err := strconv.Atoi(d.Name()); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	slices.Sort(pids)
	return pids
}

func processName(procRoot string, pid int) string {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// hexToIP converts the hex address used in /proc/net/{tcp,udp}{,6} into
// canonical text form ("127.0.0.1", "::", "fe80::1"). The kernel prints
// each 32-bit word in host byte order (little-endian on every platform the
// agent ships for), so each 4-byte group is reversed.
func hexToIP(hexAddr string) string {
	raw := make([]byte, len(hexAddr)/2)
	for i := range raw {
		b, err := strconv.ParseUint(hexAddr[i*2:i*2+2], 16, 8)
		if err != nil {
			return hexAddr
		}
		raw[i] = byte(b)
	}
	if len(raw) != 4 && len(raw) != 16 {
		return hexAddr
	}
	out := make([]byte, len(raw))
	for w := 0; w < len(raw)/4; w++ {
		for b := 0; b < 4; b++ {
			out[w*4+b] = raw[w*4+(3-b)]
		}
	}
	if len(out) == 4 {
		return netip.AddrFrom4([4]byte(out)).String()
	}
	return netip.AddrFrom16([16]byte(out)).String()
}
