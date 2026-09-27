package collector

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/swarm"
	"github.com/moby/moby/api/types/system"
	"github.com/moby/moby/client"

	"github.com/pippinmole/upkeep.sh/agent/internal/dockerapi/dockerapitest"
)

// dockerVersion is a Docker Engine /version as moby reports it.
func dockerVersion(v, api string) client.ServerVersionResult {
	return client.ServerVersionResult{
		Version: v, APIVersion: api, MinAPIVersion: "1.24", Os: "linux", Arch: "amd64",
		Components: []system.ComponentVersion{{Name: "Engine", Version: v}, {Name: "containerd"}, {Name: "runc"}},
	}
}

func TestCollectDockerEngine(t *testing.T) {
	tests := []struct {
		name      string
		version   client.ServerVersionResult
		info      system.Info
		wantEng   DockerEngine
		wantSwarm *DockerSwarm
	}{
		{
			name:    "graphdriver, not in swarm",
			version: dockerVersion("27.3.1", "1.47"),
			info: system.Info{
				Driver:          "overlay2",
				DriverStatus:    [][2]string{{"Backing Filesystem", "extfs"}, {"Supports d_type", "true"}},
				SecurityOptions: []string{"name=apparmor", "name=seccomp,profile=builtin", "name=cgroupns"},
				Swarm:           swarm.Info{LocalNodeState: swarm.LocalNodeStateInactive},
			},
			wantEng: DockerEngine{Version: "27.3.1", APIVersion: "1.47", StorageDriver: "overlay2", ImageStore: "graphdriver"},
		},
		{
			name:    "containerd image store, swarm manager",
			version: dockerVersion("29.8.0", "1.56"),
			info: system.Info{
				Driver:       "overlayfs",
				DriverStatus: [][2]string{{"driver-type", "io.containerd.snapshotter.v1"}},
				Swarm: swarm.Info{
					NodeID: "node1", LocalNodeState: swarm.LocalNodeStateActive, ControlAvailable: true,
					Cluster: &swarm.ClusterInfo{ID: "cluster1"},
				},
			},
			wantEng:   DockerEngine{Version: "29.8.0", APIVersion: "1.56", StorageDriver: "overlayfs", ImageStore: "containerd"},
			wantSwarm: &DockerSwarm{NodeID: "node1", ClusterID: "cluster1", Role: SwarmRoleManager},
		},
		{
			name:    "rootless swarm worker",
			version: dockerVersion("28.0.0", "1.48"),
			info: system.Info{
				Driver:          "overlay2",
				SecurityOptions: []string{"name=seccomp,profile=builtin", "name=rootless", "name=cgroupns"},
				Swarm:           swarm.Info{NodeID: "node2", LocalNodeState: swarm.LocalNodeStateActive},
			},
			wantEng:   DockerEngine{Version: "28.0.0", APIVersion: "1.48", StorageDriver: "overlay2", ImageStore: "graphdriver", Rootless: true},
			wantSwarm: &DockerSwarm{NodeID: "node2", Role: SwarmRoleWorker},
		},
		{
			// A locked (autolock) manager has no usable membership.
			name:    "locked swarm",
			version: dockerVersion("28.0.0", "1.48"),
			info: system.Info{
				Driver: "overlay2",
				Swarm:  swarm.Info{NodeID: "node3", LocalNodeState: swarm.LocalNodeStateLocked, ControlAvailable: true},
			},
			wantEng: DockerEngine{Version: "28.0.0", APIVersion: "1.48", StorageDriver: "overlay2", ImageStore: "graphdriver"},
		},
		{
			// Podman's compat API: no "Engine" component, containers/storage
			// driver status, no Swarm. Nothing is guessed.
			name: "podman",
			version: client.ServerVersionResult{
				Version: "5.4.0", APIVersion: "1.41",
				Components: []system.ComponentVersion{{Name: "Podman Engine", Version: "5.4.0"}},
			},
			info: system.Info{
				Driver:          "overlay",
				DriverStatus:    [][2]string{{"Backing Filesystem", "extfs"}, {"Native Overlay Diff", "true"}},
				SecurityOptions: []string{"name=seccomp,profile=default", "name=rootless"},
			},
			wantEng: DockerEngine{Version: "5.4.0", APIVersion: "1.41", StorageDriver: "overlay", Rootless: true},
		},
		{
			// Everything empty must not panic; the version falls back to
			// Info.ServerVersion.
			name:    "empty",
			info:    system.Info{ServerVersion: "1.0.0"},
			wantEng: DockerEngine{Version: "1.0.0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &dockerapitest.Fake{VersionResult: tt.version, InfoResult: tt.info}
			eng, sw, err := CollectDockerEngine(context.Background(), f)
			if err != nil {
				t.Fatal(err)
			}
			if eng != tt.wantEng {
				t.Errorf("engine = %+v, want %+v", eng, tt.wantEng)
			}
			if !reflect.DeepEqual(sw, tt.wantSwarm) {
				t.Errorf("swarm = %+v, want %+v", sw, tt.wantSwarm)
			}
		})
	}
}

func TestCollectDockerEngineErrors(t *testing.T) {
	boom := errors.New("boom")
	for name, f := range map[string]*dockerapitest.Fake{
		"version": {VersionErr: boom},
		"info":    {VersionResult: dockerVersion("29.8.0", "1.56"), InfoErr: boom},
	} {
		_, sw, err := CollectDockerEngine(context.Background(), f)
		if !errors.Is(err, boom) || !strings.Contains(err.Error(), "docker "+name) || sw != nil {
			t.Errorf("%s failure: err=%v swarm=%+v", name, err, sw)
		}
	}
}
