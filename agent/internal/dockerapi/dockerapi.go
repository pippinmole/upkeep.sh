// Package dockerapi is the agent's only way to talk to a Docker Engine (or
// Podman's Docker-compatible API): a small Client interface over the moby
// Engine API client, holding exactly the read calls the Docker collectors
// need. Collectors depend on the interface, never on the moby client
// directly, so the list below is the whole of what the agent can ask the
// engine for.
//
// The boundary (docs/decisions/docker-collection.md): access to the
// Docker socket is root on the host, and a read-only mount doesn't change
// that, so the agent's own code is what keeps it read-only. Allowed: ping,
// version, info, container list/inspect, image list/inspect, network list,
// and on Swarm managers service/task/node list. Never logs, archive/export,
// image save/get, attach/exec, events, secrets, configs, or any call that
// changes engine state. "GET-only" is not the rule: several GET endpoints
// (archive, export, image get, logs, configs) leak data. Adding a method to
// Client is a security decision; update docs/decisions/docker-collection.md with it.
//
// The engine is reached only through the configured socket path, never via
// DOCKER_HOST or other DOCKER_* variables, Docker contexts or config.json:
// with the Docker deployment's /:/host mount, the host's socket is also
// reachable at /host/run/docker.sock, and the agent must not find it there
// when Docker collection hasn't been enabled.
package dockerapi

import (
	"context"
	"errors"
	"fmt"
	"os"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/swarm"
	"github.com/moby/moby/api/types/system"
	"github.com/moby/moby/client"
	"github.com/moby/moby/client/pkg/versions"
)

// DefaultSocket is the Docker socket path used when SW_DOCKER_SOCKET is
// unset: where the socket is mounted into the agent container.
const DefaultSocket = "/var/run/docker.sock"

// MinAPIVersion is the oldest Engine API version the agent accepts: 1.41 is
// Docker Engine 20.10, and what Podman's compat API reports. Older engines
// fail with an error rather than returning partially decoded data.
const MinAPIVersion = "1.41"

// ErrSocketNotMounted means nothing exists at the socket path: Docker
// collection isn't enabled on this agent (or the host has no Docker). The
// collectors report this as skipped, not as an error. Any other failure
// (connection refused, permission denied, timeouts, too old an engine) is
// an error.
var ErrSocketNotMounted = errors.New("docker socket not mounted")

// IsNotFound reports whether err is the engine's 404 for an object that
// doesn't exist (any more): a container or image removed between a list
// and the inspect that follows it.
func IsNotFound(err error) bool { return cerrdefs.IsNotFound(err) }

// Client is the complete set of Engine API calls the agent makes. Every
// method is a read. List methods return every item (containers include
// stopped ones); callers apply their own caps.
type Client interface {
	// Ping returns the /_ping headers: API version, OS type, and the Swarm
	// node state and role, which tell a manager from a worker without a
	// call to Info.
	Ping(ctx context.Context) (client.PingResult, error)
	// Version is GET /version. The moby client returns its own struct here
	// rather than the API type; it carries the same fields.
	Version(ctx context.Context) (client.ServerVersionResult, error)
	Info(ctx context.Context) (system.Info, error)

	ContainerList(ctx context.Context) ([]container.Summary, error)
	ContainerInspect(ctx context.Context, id string) (container.InspectResponse, error)
	ImageList(ctx context.Context) ([]image.Summary, error)
	ImageInspect(ctx context.Context, id string) (image.InspectResponse, error)
	NetworkList(ctx context.Context) ([]network.Summary, error)

	// Swarm, managers only: workers get an error from the engine.
	// ServiceList includes running/desired task counts (ServiceStatus).
	ServiceList(ctx context.Context) ([]swarm.Service, error)
	TaskList(ctx context.Context) ([]swarm.Task, error)
	NodeList(ctx context.Context) ([]swarm.Node, error)

	Close() error
}

// Engine is the Client backed by a real engine socket.
type Engine struct {
	// c is unexported so nothing outside this package can reach the rest
	// of the moby client's API.
	c *client.Client
}

var _ Client = (*Engine)(nil)

// Open connects to the engine at socketPath, negotiates the API version and
// checks it against MinAPIVersion. It returns an error wrapping
// ErrSocketNotMounted when nothing is at socketPath (or it is a directory:
// Docker creates an empty directory for a bind mount whose host path is
// missing). The caller must Close the returned Engine.
func Open(ctx context.Context, socketPath string) (*Engine, error) {
	if err := checkSocketPath(socketPath); err != nil {
		return nil, err
	}
	// No FromEnv / WithHostFromEnv / WithAPIVersionFromEnv: only the
	// configured socket, and API version negotiation (on by default).
	c, err := client.New(client.WithHost("unix://" + socketPath))
	if err != nil {
		return nil, fmt.Errorf("docker client for %s: %w", socketPath, err)
	}
	e := &Engine{c: c}
	if _, err := e.Ping(ctx); err != nil {
		c.Close()
		return nil, fmt.Errorf("docker engine at %s: %w", socketPath, err)
	}
	return e, nil
}

func checkSocketPath(socketPath string) error {
	fi, err := os.Stat(socketPath)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: nothing at %s", ErrSocketNotMounted, socketPath)
	}
	if err != nil {
		return fmt.Errorf("docker socket: %w", err)
	}
	if fi.IsDir() {
		return fmt.Errorf("%w: %s is a directory", ErrSocketNotMounted, socketPath)
	}
	return nil
}

// CheckAPIVersion reports whether an engine's API version (as its /_ping
// or /version reports it, e.g. "1.47") is at least MinAPIVersion. An engine
// that reports no version predates version negotiation and is rejected.
func CheckAPIVersion(v string) error {
	if v == "" {
		return fmt.Errorf("docker engine reported no API version (need %s or newer)", MinAPIVersion)
	}
	if versions.LessThan(v, MinAPIVersion) {
		return fmt.Errorf("docker engine API version %s is too old (need %s or newer, Docker Engine 20.10+)", v, MinAPIVersion)
	}
	return nil
}

// Ping negotiates the API version on first use and checks it against
// MinAPIVersion on every call.
func (e *Engine) Ping(ctx context.Context) (client.PingResult, error) {
	p, err := e.c.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true})
	// The moby client refuses engines below its own minimum (1.40) with
	// its own message; when the engine did answer with a version, report
	// ours instead, which says what's needed.
	if p.APIVersion != "" || err == nil {
		if verr := CheckAPIVersion(p.APIVersion); verr != nil {
			return p, verr
		}
	}
	return p, err
}

func (e *Engine) Version(ctx context.Context) (client.ServerVersionResult, error) {
	return e.c.ServerVersion(ctx, client.ServerVersionOptions{})
}

func (e *Engine) Info(ctx context.Context) (system.Info, error) {
	r, err := e.c.Info(ctx, client.InfoOptions{})
	return r.Info, err
}

func (e *Engine) ContainerList(ctx context.Context) ([]container.Summary, error) {
	r, err := e.c.ContainerList(ctx, client.ContainerListOptions{All: true})
	return r.Items, err
}

func (e *Engine) ContainerInspect(ctx context.Context, id string) (container.InspectResponse, error) {
	r, err := e.c.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	return r.Container, err
}

func (e *Engine) ImageList(ctx context.Context) ([]image.Summary, error) {
	r, err := e.c.ImageList(ctx, client.ImageListOptions{})
	return r.Items, err
}

func (e *Engine) ImageInspect(ctx context.Context, id string) (image.InspectResponse, error) {
	r, err := e.c.ImageInspect(ctx, id)
	return r.InspectResponse, err
}

func (e *Engine) NetworkList(ctx context.Context) ([]network.Summary, error) {
	r, err := e.c.NetworkList(ctx, client.NetworkListOptions{})
	return r.Items, err
}

func (e *Engine) ServiceList(ctx context.Context) ([]swarm.Service, error) {
	r, err := e.c.ServiceList(ctx, client.ServiceListOptions{Status: true})
	return r.Items, err
}

func (e *Engine) TaskList(ctx context.Context) ([]swarm.Task, error) {
	r, err := e.c.TaskList(ctx, client.TaskListOptions{})
	return r.Items, err
}

func (e *Engine) NodeList(ctx context.Context) ([]swarm.Node, error) {
	r, err := e.c.NodeList(ctx, client.NodeListOptions{})
	return r.Items, err
}

func (e *Engine) Close() error { return e.c.Close() }
