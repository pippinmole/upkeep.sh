package collector

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// CollectDeletedLibs finds processes that still map a shared library that
// has since been deleted from disk: after `apt upgrade` replaces libssl,
// every process started before it keeps running the old code until it is
// restarted. This is the needrestart / checkrestart signal, read from
// /proc/<pid>/maps, where the kernel suffixes such mappings " (deleted)".
//
// Only mappings of shared objects count: an absolute path whose file name
// contains ".so" ("libssl.so.3", "libc.so.6"). Deleted non-library
// mappings (memfd:, /dev/shm, SysV shm, deleted temp files) are not
// upgrade leftovers and are ignored.
//
// units (pid -> systemd service, from ProcessUnits) labels each process
// with the service to restart; it may be nil.
//
// Reading another user's maps needs ptrace read access; the agent runs
// with every capability dropped, so those processes are counted in
// UnreadableProcesses rather than failing the collector. Processes that
// exit mid-scan are skipped.
func CollectDeletedLibs(procRoot string, units map[int]string) (NeedsRestart, error) {
	if _, err := os.Stat(procRoot); err != nil {
		return NeedsRestart{}, err
	}
	res := NeedsRestart{Processes: []DeletedLibProcess{}}
	for _, pid := range listPIDs(procRoot) {
		libs, err := deletedLibsOf(filepath.Join(procRoot, strconv.Itoa(pid), "maps"))
		if errors.Is(err, fs.ErrPermission) {
			res.UnreadableProcesses++
			continue
		} else if err != nil || len(libs) == 0 {
			continue
		}
		if len(res.Processes) == MaxDeletedLibProcesses {
			res.Truncated = true
			continue // keep counting unreadable processes
		}
		if len(libs) > MaxDeletedLibsPerProcess {
			libs = libs[:MaxDeletedLibsPerProcess]
		}
		res.Processes = append(res.Processes, DeletedLibProcess{
			PID:       pid,
			Name:      processName(procRoot, pid),
			Unit:      units[pid],
			Libraries: libs,
		})
	}
	return res, nil
}

// deletedLibsOf returns the sorted, unique deleted shared objects mapped
// in one maps file. The pathname is the sixth field and may contain
// spaces, so it is taken as everything after the fifth.
func deletedLibsOf(mapsPath string) ([]string, error) {
	f, err := os.Open(mapsPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var libs []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		p, ok := strings.CutSuffix(line, " (deleted)")
		if !ok {
			continue
		}
		p = mapsPathname(p)
		if !strings.HasPrefix(p, "/") || !strings.Contains(path.Base(p), ".so") {
			continue
		}
		libs = append(libs, p)
	}
	// A read error part-way (the process exited) still leaves a valid prefix.
	slices.Sort(libs)
	return slices.Compact(libs), nil
}

// mapsPathname returns the pathname field of a maps line: the text after
// the five fixed fields (address, perms, offset, dev, inode), trimmed.
func mapsPathname(line string) string {
	rest := line
	for range 5 {
		rest = strings.TrimLeft(rest, " ")
		sp := strings.IndexByte(rest, ' ')
		if sp < 0 {
			return ""
		}
		rest = rest[sp:]
	}
	return strings.TrimSpace(rest)
}
