// Package dockerapitest provides a canned dockerapi.Client for testing the
// Docker collectors without an engine.
package dockerapitest

import (
	"context"
	"fmt"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/swarm"
	"github.com/moby/moby/api/types/system"
	"github.com/moby/moby/client"

	"github.com/pippinmole/upkeep.sh/agent/internal/dockerapi"
)

// Fake answers every call from its fields. A call returns its *Err field
// when set, else the canned value. Inspect calls look the id up in the
// map and return a not-found error (dockerapi.IsNotFound, like the
// engine's 404) when it's missing.
type Fake struct {
	PingResult client.PingResult
	PingErr    error

	VersionResult client.ServerVersionResult
	VersionErr    error

	InfoResult system.Info
	InfoErr    error

	Containers          []container.Summary
	ContainersErr       error
	ContainerInspects   map[string]container.InspectResponse
	ContainerInspectErr error

	Images          []image.Summary
	ImagesErr       error
	ImageInspects   map[string]image.InspectResponse
	ImageInspectErr error

	Networks    []network.Summary
	NetworksErr error

	Services    []swarm.Service
	ServicesErr error
	Tasks       []swarm.Task
	TasksErr    error
	Nodes       []swarm.Node
	NodesErr    error

	// Closed is set by Close.
	Closed bool
}

var _ dockerapi.Client = (*Fake)(nil)

func (f *Fake) Ping(context.Context) (client.PingResult, error) { return f.PingResult, f.PingErr }

func (f *Fake) Version(context.Context) (client.ServerVersionResult, error) {
	return f.VersionResult, f.VersionErr
}

func (f *Fake) Info(context.Context) (system.Info, error) { return f.InfoResult, f.InfoErr }

func (f *Fake) ContainerList(context.Context) ([]container.Summary, error) {
	return f.Containers, f.ContainersErr
}

func (f *Fake) ContainerInspect(_ context.Context, id string) (container.InspectResponse, error) {
	if f.ContainerInspectErr != nil {
		return container.InspectResponse{}, f.ContainerInspectErr
	}
	r, ok := f.ContainerInspects[id]
	if !ok {
		return r, fmt.Errorf("no such container: %s: %w", id, cerrdefs.ErrNotFound)
	}
	return r, nil
}

func (f *Fake) ImageList(context.Context) ([]image.Summary, error) { return f.Images, f.ImagesErr }

func (f *Fake) ImageInspect(_ context.Context, id string) (image.InspectResponse, error) {
	if f.ImageInspectErr != nil {
		return image.InspectResponse{}, f.ImageInspectErr
	}
	r, ok := f.ImageInspects[id]
	if !ok {
		return r, fmt.Errorf("no such image: %s: %w", id, cerrdefs.ErrNotFound)
	}
	return r, nil
}

func (f *Fake) NetworkList(context.Context) ([]network.Summary, error) {
	return f.Networks, f.NetworksErr
}

func (f *Fake) ServiceList(context.Context) ([]swarm.Service, error) {
	return f.Services, f.ServicesErr
}

func (f *Fake) TaskList(context.Context) ([]swarm.Task, error) { return f.Tasks, f.TasksErr }

func (f *Fake) NodeList(context.Context) ([]swarm.Node, error) { return f.Nodes, f.NodesErr }

func (f *Fake) Close() error {
	f.Closed = true
	return nil
}
