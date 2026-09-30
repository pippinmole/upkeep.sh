package imagescan

import (
	"bytes"
	"os"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

func childSysProcAttr() *syscall.SysProcAttr {
	// The child dies with the worker, so a killed worker leaves no
	// catalog running (its temp dir is swept on the next start).
	return &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

// watchMemory polls p's resident set size and kills it once it goes over
// limit, setting over. The returned func stops the watchdog.
func watchMemory(p *os.Process, limit int64, over *atomic.Bool) (stop func()) {
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if rss, ok := residentBytes(p.Pid); ok && rss > limit {
					over.Store(true)
					_ = p.Kill()
					return
				}
			}
		}
	}()
	return func() { close(done) }
}

// residentBytes reads VmRSS from /proc/<pid>/status.
func residentBytes(pid int) (int64, bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0, false
	}
	for _, line := range bytes.Split(b, []byte("\n")) {
		rest, ok := bytes.CutPrefix(line, []byte("VmRSS:"))
		if !ok {
			continue
		}
		f := bytes.Fields(rest) // "123456 kB"
		if len(f) < 1 {
			return 0, false
		}
		kb, err := strconv.ParseInt(string(f[0]), 10, 64)
		return kb * 1024, err == nil
	}
	return 0, false
}
