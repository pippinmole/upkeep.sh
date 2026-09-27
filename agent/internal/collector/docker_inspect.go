package collector

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"unicode/utf8"

	"github.com/pippinmole/upkeep.sh/agent/internal/dockerapi"
)

// dockerInspectConcurrency bounds the inspect calls one collector has in
// flight. Inspects are one call per container / image, answered from the
// engine's memory, so a few in parallel keep a host with hundreds of
// objects well inside the snapshot's Docker budget without loading the
// daemon; more buys little over a unix socket.
const dockerInspectConcurrency = 4

// errDockerGone marks an object whose inspect got the engine's 404: it was
// removed between the list and its inspect, so it is left out.
var errDockerGone = errors.New("docker object gone")

// dockerInspectAll inspects every id (at most dockerInspectConcurrency at
// a time, each call under DockerCallTimeout) and returns the results in
// ids' order, with errs[i] saying how ids[i] went:
//
//   - nil: out[i] holds the inspect.
//   - errDockerGone: the engine's 404; the object is gone, leave it out.
//   - any other error: the inspect failed; the caller reports the object
//     as a partial entry from its list data (DockerInspectErrorMax
//     explains why it isn't dropped). A single call timing out
//     (DockerCallTimeout) while the collector's context is still live is
//     one of these.
//
// err is set only when ctx itself ends before every inspect succeeded (the
// snapshot's Docker budget ran out, or the agent is stopping): then the
// failures say nothing about the objects, and the collector fails rather
// than send a list of partial entries.
func dockerInspectAll[R any](ctx context.Context, what string, ids []string,
	inspect func(context.Context, string) (R, error)) (out []R, errs []error, err error) {
	out = make([]R, len(ids))
	errs = make([]error, len(ids))
	var (
		wg      sync.WaitGroup
		stopped bool
		anyErr  bool
		mu      sync.Mutex
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
			cctx, cancel := context.WithTimeout(ctx, DockerCallTimeout)
			r, err := inspect(cctx, id)
			cancel()
			switch {
			case err == nil:
				out[i] = r
			case dockerapi.IsNotFound(err):
				errs[i] = errDockerGone
			default:
				errs[i] = err
				mu.Lock()
				anyErr = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if stopped || (anyErr && ctx.Err() != nil) {
		return nil, nil, fmt.Errorf("docker %s inspect: %w", what, context.Cause(ctx))
	}
	return out, errs, nil
}

// dockerInspectError is err's text for an InspectError field, cut to
// DockerInspectErrorMax bytes on a rune boundary.
func dockerInspectError(err error) string {
	s := err.Error()
	if len(s) <= DockerInspectErrorMax {
		return s
	}
	i := DockerInspectErrorMax
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i]
}
