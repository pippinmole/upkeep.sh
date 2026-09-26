// Command agent is the security-whatnot host agent: a small, read-only,
// outbound-only fact collector. It never accepts inbound connections and
// never executes commands on behalf of the server.
package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/icondesk/security-whatnot/agent/internal/collector"
	"github.com/icondesk/security-whatnot/agent/internal/transport"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	serverURL := envOr("SW_SERVER_URL", "")
	if serverURL == "" {
		log.Fatal("SW_SERVER_URL is required")
	}
	dataDir := envOr("SW_DATA_DIR", "/var/lib/security-whatnot")
	interval := 15 * time.Minute
	if v := os.Getenv("SW_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			interval = d
		}
	}

	client := transport.New(serverURL)
	credPath := filepath.Join(dataDir, "credentials.json")

	agentID, agentSecret, err := loadOrEnroll(client, credPath)
	if err != nil {
		log.Fatalf("enrollment failed: %v", err)
	}

	for {
		snap, err := collectSnapshot()
		if err != nil {
			log.Printf("collect failed: %v", err)
		} else if err := client.PushSnapshot(agentID, agentSecret, snap); err != nil {
			log.Printf("push failed: %v", err)
		} else {
			log.Printf("pushed snapshot: %d packages, %d listening sockets", len(snap.Packages), len(snap.ListeningSockets))
		}
		time.Sleep(interval)
	}
}

func collectSnapshot() (collector.Snapshot, error) {
	pkgs, err := collector.CollectPackages(collector.DefaultDpkgStatusPath)
	if err != nil {
		return collector.Snapshot{}, err
	}
	osRelease, err := collector.CollectOSRelease(collector.DefaultOSReleasePath)
	if err != nil {
		return collector.Snapshot{}, err
	}
	sockets, err := collector.CollectListeningSockets("/proc")
	if err != nil {
		return collector.Snapshot{}, err
	}
	rebootRequired, rebootPkgs := collector.CollectRebootRequired(
		collector.DefaultRebootRequiredPath, collector.DefaultRebootRequiredPkgsPath)

	// Best-effort only: CollectPublicIPs cannot fail/error by design, so it
	// can never short-circuit the rest of collection the way the collectors
	// above do on their first error.
	pubIPCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	publicIPv4, publicIPv6 := collector.CollectPublicIPs(pubIPCtx)

	return collector.Snapshot{
		SchemaVersion:    collector.SchemaVersion,
		CollectedAt:      time.Now().UTC().Format(time.RFC3339),
		OS:               osRelease,
		Packages:         pkgs,
		ListeningSockets: sockets,
		RebootRequired:   rebootRequired,
		RebootPackages:   rebootPkgs,
		PublicIPv4:       publicIPv4,
		PublicIPv6:       publicIPv6,
	}, nil
}
