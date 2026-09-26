// Command agent is the security-whatnot host agent: a small, read-only,
// outbound-only fact collector. It never accepts inbound connections and
// never executes commands on behalf of the server.
package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/pippinmole/upkeep.sh/agent/internal/collector"
	"github.com/pippinmole/upkeep.sh/agent/internal/snapshot"
	"github.com/pippinmole/upkeep.sh/agent/internal/target"
	"github.com/pippinmole/upkeep.sh/agent/internal/transport"
)

// version is the agent build version, set at build time with
// -ldflags "-X main.version=...".
var version = "dev"

// platform is the agent binary's GOOS/GOARCH.
func platform() string { return runtime.GOOS + "/" + runtime.GOARCH }

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

	// One target today: the host the agent runs on, visible read-only under
	// SW_HOST_ROOT (the /:/host bind mount in Docker; "/" for a bare-metal
	// install). Remote targets would be added to this list once remote
	// collection is designed (see internal/target).
	hostRoot := envOr("SW_HOST_ROOT", "/host")
	targets := []target.Target{target.NewLocal(hostRoot, "/proc")}
	collect := snapshot.New()
	collect.Agent = &collector.Agent{Version: version, Platform: platform(), IntervalSeconds: int(interval.Seconds())}

	for {
		for _, t := range targets {
			snap := collect.Collect(context.Background(), t)
			logCollectorErrors(t, snap)
			if err := client.PushSnapshot(agentID, agentSecret, snap); err != nil {
				log.Printf("[%s] push failed: %v", t.Ref(), err)
			} else {
				log.Printf("[%s] pushed snapshot: os=%s/%s, %d packages, %d listening sockets",
					t.Ref(), snap.Host.OSFamily, snap.OS.ID, len(snap.Packages), len(snap.ListeningSockets))
			}
		}
		time.Sleep(interval)
	}
}

// logCollectorErrors surfaces failed collectors locally. They are also in
// the pushed snapshot, but an operator tailing the container log should not
// have to query the server to see that, say, the dpkg database is unreadable.
func logCollectorErrors(t target.Target, snap collector.Snapshot) {
	names := make([]string, 0, len(snap.Collectors))
	for name := range snap.Collectors {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if st := snap.Collectors[name]; st.Status == collector.StatusError {
			log.Printf("[%s] collector %s failed: %s", t.Ref(), name, st.Error)
		}
	}
}
