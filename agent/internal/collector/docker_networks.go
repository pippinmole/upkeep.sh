package collector

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	"github.com/moby/moby/api/types/network"

	"github.com/pippinmole/upkeep.sh/agent/internal/dockerapi"
)

// CollectDockerNetworks lists the engine's networks (GET /networks) and
// maps each onto DockerNetwork. The list carries everything needed, so
// there is no inspect. truncated is true when the network list or any
// network's subnets hit their cap.
//
// Options, labels, peers and the IPAM driver's options are never read.
func CollectDockerNetworks(ctx context.Context, c dockerapi.Client) (networks []DockerNetwork, truncated bool, err error) {
	lctx, cancel := context.WithTimeout(ctx, DockerCallTimeout)
	list, err := c.NetworkList(lctx)
	cancel()
	if err != nil {
		return nil, false, fmt.Errorf("docker network list: %w", err)
	}

	slices.SortFunc(list, func(a, b network.Summary) int { return cmp.Compare(a.ID, b.ID) })
	list = slices.CompactFunc(list, func(a, b network.Summary) bool { return a.ID == b.ID })
	if len(list) > MaxDockerNetworks {
		list, truncated = list[:MaxDockerNetworks], true
	}
	networks = make([]DockerNetwork, 0, len(list))
	for _, n := range list {
		nw, cut := dockerNetwork(n)
		truncated = truncated || cut
		networks = append(networks, nw)
	}
	return networks, truncated, nil
}

func dockerNetwork(n network.Summary) (DockerNetwork, bool) {
	out := DockerNetwork{ID: n.ID, Name: n.Name, Driver: n.Driver, Scope: n.Scope, Internal: n.Internal}
	var subnets []string
	for _, cfg := range n.IPAM.Config {
		if cfg.Subnet.IsValid() {
			subnets = append(subnets, cfg.Subnet.String())
		}
	}
	slices.Sort(subnets)
	subnets = slices.Compact(subnets)
	var cut bool
	out.Subnets, cut = capList(subnets, MaxDockerSubnetsPerNetwork)
	return out, cut
}
