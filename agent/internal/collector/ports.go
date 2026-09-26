package collector

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CollectListeningSockets reads /proc/net/tcp{,6} and maps each LISTEN
// socket to its owning process by scanning /proc/<pid>/fd for matching
// socket inodes. It relies on the agent container sharing the host's PID
// and network namespaces (pid: host, network_mode: host) so that native
// /proc is accurate for the host, not the container.
func CollectListeningSockets(procRoot string) ([]Socket, error) {
	var sockets []Socket

	for _, spec := range []struct {
		proto string
		path  string
	}{
		{"tcp", filepath.Join(procRoot, "net", "tcp")},
		{"tcp6", filepath.Join(procRoot, "net", "tcp6")},
	} {
		entries, err := parseProcNetTCP(spec.path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for i := range entries {
			entries[i].Proto = spec.proto
		}
		sockets = append(sockets, entries...)
	}

	inodeToPID := buildInodeToPIDMap(procRoot)
	for i, s := range sockets {
		if pid, ok := inodeToPID[s.inode]; ok {
			sockets[i].PID = pid
			sockets[i].ProcessName = processName(procRoot, pid)
		}
	}
	return sockets, nil
}

// parseProcNetTCP parses the LISTEN (state 0A) rows of /proc/net/tcp(6).
// The inode is carried on the returned struct via an unexported field
// used only to build the pid map, then dropped from the JSON payload.
func parseProcNetTCP(path string) ([]Socket, error) {
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
		state := fields[3]
		if state != "0A" { // TCP_LISTEN
			continue
		}
		local := fields[1]
		addrPort := strings.Split(local, ":")
		if len(addrPort) != 2 {
			continue
		}
		port, err := strconv.ParseInt(addrPort[1], 16, 32)
		if err != nil {
			continue
		}
		ino, _ := strconv.Atoi(fields[9])
		out = append(out, Socket{
			LocalAddr: hexToIP(addrPort[0]),
			Port:      int(port),
			inode:     ino,
		})
	}
	return out, sc.Err()
}

func buildInodeToPIDMap(procRoot string) map[int]int {
	m := map[int]int{}
	pidDirs, err := os.ReadDir(procRoot)
	if err != nil {
		return m
	}
	for _, d := range pidDirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join(procRoot, d.Name(), "fd")
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
				m[inode] = pid
			}
		}
	}
	return m
}

func processName(procRoot string, pid int) string {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// hexToIP converts the big-endian hex address used in /proc/net/tcp{,6}
// into dotted/colon notation. IPv4 words are little-endian per octet group.
func hexToIP(hexAddr string) string {
	raw := make([]byte, len(hexAddr)/2)
	for i := range raw {
		b, err := strconv.ParseUint(hexAddr[i*2:i*2+2], 16, 8)
		if err != nil {
			return hexAddr
		}
		raw[i] = byte(b)
	}
	if len(raw) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", raw[3], raw[2], raw[1], raw[0])
	}
	// IPv6: stored as four little-endian 32-bit words; reverse each word's bytes.
	if len(raw) == 16 {
		out := make([]byte, 16)
		for w := 0; w < 4; w++ {
			for b := 0; b < 4; b++ {
				out[w*4+b] = raw[w*4+(3-b)]
			}
		}
		return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
			out[0:2], out[2:4], out[4:6], out[6:8], out[8:10], out[10:12], out[12:14], out[14:16])
	}
	return hexAddr
}
