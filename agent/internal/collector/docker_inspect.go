package collector

import (
	"context"
	"fmt"
	"sync"

	"github.com/pippinmole/upkeep.sh/agent/internal/dockerapi"
)

// dockerInspectConcurrency bounds the inspect calls one collector has in
// flight. Inspects are one call per container / image, answered from the
// engine's memory, so a few in parallel keep a host with hundreds of
// objects well inside the snapshot's Docker budget without loading the
// daemon; more buys little over a unix socket.
const dockerInspectConcurrency = 4

// dockerInspectAll inspects every id (at most dockerInspectConcurrency at
// a time, each call under DockerCallTimeout) and returns the results in
// ids' order. found[i] is false when ids[i] no longer exists (the engine's
// 404): it was removed between the list and its inspect, which is not an
// error, the object is just gone.
//
// Any other failure fails the whole call, and cancels the inspects still
// running: a list with an object silently missing would be read as that
// object having been removed, and it isn't a deterministic prefix either,
// which is all a truncated list may be (CollectorStatus.Truncated).
func dockerInspectAll[R any](ctx context.Context, what string, ids []string,
	inspect func(context.Context, string) (R, error)) (out []R, found []bool, err error) {
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	out = make([]R, len(ids))
	found = make([]bool, len(ids))
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		stopped  bool
	)
	sem := make(chan struct{}, dockerInspectConcurrency)
launch:
	for i, id := range ids {
		if ctx.Err() != nil {
			stopped = true
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			stopped = true
			break launch
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			cctx, ccancel := context.WithTimeout(ctx, DockerCallTimeout)
			r, err := inspect(cctx, id)
			ccancel()
			switch {
			case err == nil:
				out[i], found[i] = r, true
			case dockerapi.IsNotFound(err):
			default:
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("docker %s inspect %s: %w", what, id, err)
					cancel()
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return nil, nil, firstErr
	}
	// With no inspect error, the launch loop stops early only when the
	// caller's context ended: the ids not yet launched were never looked at.
	if stopped {
		return nil, nil, fmt.Errorf("docker %s inspect: %w", what, context.Cause(parent))
	}
	return out, found, nil
}
