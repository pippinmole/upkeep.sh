package collector

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"github.com/moby/moby/api/types/network"

	"github.com/pippinmole/upkeep.sh/agent/internal/dockerapi/dockerapitest"
)

func netSummary(n network.Network) network.Summary { return network.Summary{Network: n} }

func TestCollectDockerNetworks(t *testing.T) {
	f := &dockerapitest.Fake{Networks: []network.Summary{
		netSummary(network.Network{
			ID: "n2", Name: "myapp_default", Driver: "bridge", Scope: "local",
			Options: map[string]string{"com.docker.network.bridge.name": "br-x"},
			Labels:  map[string]string{"com.docker.compose.network": "default"},
			IPAM: network.IPAM{Config: []network.IPAMConfig{
				{Subnet: netip.MustParsePrefix("fd00:1::/64")},
				{Subnet: netip.MustParsePrefix("172.18.0.0/16"), Gateway: netip.MustParseAddr("172.18.0.1")},
				{Subnet: netip.MustParsePrefix("172.18.0.0/16")},
				{}, // no subnet
			}},
		}),
		netSummary(network.Network{ID: "n1", Name: "none", Driver: "null", Scope: "local"}),
		netSummary(network.Network{
			ID: "n3", Name: "backend", Driver: "overlay", Scope: "swarm", Internal: true,
			IPAM: network.IPAM{Config: []network.IPAMConfig{{Subnet: netip.MustParsePrefix("10.0.1.0/24")}}},
		}),
	}}
	got, truncated, err := CollectDockerNetworks(context.Background(), f)
	if err != nil || truncated {
		t.Fatalf("truncated %v, err %v", truncated, err)
	}
	want := []DockerNetwork{
		{ID: "n1", Name: "none", Driver: "null", Scope: "local"},
		{ID: "n2", Name: "myapp_default", Driver: "bridge", Scope: "local", Subnets: []string{"172.18.0.0/16", "fd00:1::/64"}},
		{ID: "n3", Name: "backend", Driver: "overlay", Scope: "swarm", Internal: true, Subnets: []string{"10.0.1.0/24"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("networks = %+v\nwant %+v", got, want)
	}

	f.NetworksErr = errors.New("boom")
	if _, _, err := CollectDockerNetworks(context.Background(), f); err == nil {
		t.Error("list error not reported")
	}
}

func TestCollectDockerNetworksCaps(t *testing.T) {
	f := &dockerapitest.Fake{}
	for i := MaxDockerNetworks; i >= 0; i-- {
		f.Networks = append(f.Networks, netSummary(network.Network{ID: fmt.Sprintf("n%04d", i)}))
	}
	got, truncated, err := CollectDockerNetworks(context.Background(), f)
	if err != nil || !truncated || len(got) != MaxDockerNetworks || got[0].ID != "n0000" {
		t.Errorf("%d networks, truncated %v, err %v", len(got), truncated, err)
	}

	var cfg []network.IPAMConfig
	for i := range MaxDockerSubnetsPerNetwork + 1 {
		cfg = append(cfg, network.IPAMConfig{Subnet: netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/16", 100+i))})
	}
	nw, cut := dockerNetwork(netSummary(network.Network{ID: "x", IPAM: network.IPAM{Config: cfg}}))
	if !cut || len(nw.Subnets) != MaxDockerSubnetsPerNetwork || nw.Subnets[0] != "10.100.0.0/16" {
		t.Errorf("subnets = %v, cut %v", nw.Subnets, cut)
	}
}
