package imagescan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// The catalog step runs in a child process: the worker binary re-executed
// with the hidden CatalogCommand. Syft is a library with no knobs for
// its own CPU or memory use, and a goroutine can't be killed, so the
// child is what makes the bounds hard:
//
//   - CPU: GOMAXPROCS=Config.CPUs (and Syft's parallelism to match).
//   - Memory: GOMEMLIMIT at 80% of Config.MemoryBytes makes the GC work
//     harder before the limit; on Linux a watchdog kills the child when
//     its RSS goes over MemoryBytes (the result: KindMemory). A cgroup
//     would be stricter but needs privileges the worker container
//     doesn't have; RLIMIT_AS breaks the Go runtime's address space
//     reservations.
//   - Time: killed (SIGKILL) when the scan's deadline passes, and on
//     Linux when the worker itself dies (Pdeathsig).
//   - Crashes, panics and OOM kills stay in the child; the worker only
//     sees a failed scan.
//
// The child reads only the extracted rootfs and writes its Result as
// JSON to stdout.

// maxResultBytes caps the child's stdout (a large image's list is a few
// MiB).
const maxResultBytes = 256 << 20

// catalog runs the child over rootfs.
func (s *Scanner) catalog(ctx context.Context, rootfs string) (*Result, error) {
	argv := s.cfg.Command
	if len(argv) == 0 {
		exe, err := os.Executable()
		if err != nil {
			return nil, &Error{Kind: KindFailed, Err: fmt.Errorf("catalog: %w", err)}
		}
		argv = []string{exe, CatalogCommand}
	}
	cmd := exec.CommandContext(ctx, argv[0], append(argv[1:], rootfs)...) //nolint:gosec // argv is this binary or test config, not request input
	cmd.Env = append(childEnv(os.Environ()),
		"GOMAXPROCS="+strconv.Itoa(s.cfg.CPUs),
		"GOMEMLIMIT="+strconv.FormatInt(s.cfg.MemoryBytes/10*8, 10))
	cmd.Dir = rootfs
	cmd.SysProcAttr = childSysProcAttr()
	cmd.WaitDelay = 5 * time.Second
	var stdout limitedBuffer
	stdout.max = maxResultBytes
	var stderr tailBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	if err := cmd.Start(); err != nil {
		return nil, &Error{Kind: KindFailed, Err: fmt.Errorf("catalog: start: %w", err)}
	}
	var overMemory atomic.Bool
	stopWatch := watchMemory(cmd.Process, s.cfg.MemoryBytes, &overMemory)
	err := cmd.Wait()
	stopWatch()

	switch {
	case overMemory.Load():
		return nil, &Error{Kind: KindMemory, Err: fmt.Errorf("catalog used more than %d bytes of memory", s.cfg.MemoryBytes)}
	case ctx.Err() != nil:
		return nil, ctx.Err() // Scan turns a deadline into KindTimeout
	case err != nil:
		return nil, &Error{Kind: KindFailed, Err: fmt.Errorf("catalog: %w: %s", err, stderr.String())}
	case stdout.over:
		return nil, &Error{Kind: KindFailed, Err: errors.New("catalog: result over the size limit")}
	}
	var res Result
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		return nil, &Error{Kind: KindFailed, Err: fmt.Errorf("catalog: result: %w", err)}
	}
	return &res, nil
}

// childEnv is the worker's environment without what the child must not
// have: its own GOMAXPROCS / GOMEMLIMIT come from Config, and it needs no
// credentials (it never touches the database or the network).
func childEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		switch {
		case k == "GOMAXPROCS", k == "GOMEMLIMIT", k == "DATABASE_URL", strings.HasPrefix(k, "SW_"):
			continue
		}
		out = append(out, kv)
	}
	return out
}

// RunChild is the catalog child's main: `worker syft-catalog <rootfs>`.
// It writes the Result as JSON to stdout.
func RunChild(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: %s <rootfs>", CatalogCommand)
	}
	res, err := Catalog(context.Background(), args[0], runtime.GOMAXPROCS(0))
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(res)
}

// limitedBuffer keeps at most max bytes and notes that more came.
type limitedBuffer struct {
	bytes.Buffer
	max  int
	over bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		b.over = true
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// tailBuffer keeps the last 4 KiB written (the child's stderr, for the
// log).
type tailBuffer struct{ b []byte }

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > 4096 {
		t.b = t.b[len(t.b)-4096:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return strings.TrimSpace(string(t.b)) }
