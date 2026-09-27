// Command agent is the upkeep host agent: a small, read-only,
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
	dataDir := resolveDataDir()
	interval := 15 * time.Minute
	if v := os.Getenv("SW_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			interval = d
		}
	}

	client := transport.New(serverURL)
	credPath := filepath.Join(dataDir, "credentials.json")

	creds, err := loadOrEnroll(client, credPath)
	if err != nil {
		log.Fatalf("enrollment failed: %v", err)
	}

	// The host the agent runs on, visible read-only under SW_HOST_ROOT
	// (the /:/host bind mount in Docker; "/" for a bare-metal install).
	hostRoot := envOr("SW_HOST_ROOT", "/host")
	local := target.NewLocal(hostRoot, "/proc")
	collect := snapshot.New()
	collect.Agent = &collector.Agent{Version: version, Platform: platform(), IntervalSeconds: int(interval.Seconds())}

	// Remote targets (hosts added in the dashboard, read over SFTP) need
	// the agent's SSH key. Without one the agent still collects its own
	// machine.
	var remote *remoteRunner
	keyPath, keyFromEnv := os.LookupEnv("SW_SSH_KEY_FILE")
	if !keyFromEnv {
		keyPath = filepath.Join(dataDir, "ssh", "id_ed25519")
	}
	if signer, err := loadOrCreateSSHKey(keyPath, !keyFromEnv); err != nil {
		log.Printf("remote targets disabled: ssh key %s: %v", keyPath, err)
	} else {
		remote = newRemoteRunner(client, signer, collect, interval)
		log.Printf("ssh public key for remote targets: %s", remote.pubLine)
	}

	ctx := context.Background()
	var nextLocal time.Time
	for {
		now := time.Now()
		rotate := false
		if !now.Before(nextLocal) {
			rotate = pushLocal(ctx, client, collect, local, creds)
			nextLocal = now.Add(interval)
		}
		if remote != nil {
			remote.poll(creds, now)
			rotate = remote.runDue(ctx, creds, now) || rotate
		}
		// Credential rotation is agent-initiated: the server only asks (a
		// push response header); nothing it sends is ever executed.
		if rotate {
			if next, err := rotateCredentials(client, credPath, creds); err != nil {
				log.Printf("credential rotation failed: %v", err)
			} else {
				creds = next
				log.Printf("credentials rotated and saved to %s", credPath)
			}
		}
		wake := nextLocal
		if remote != nil && !remote.unsupported {
			if poll := time.Now().Add(configPollInterval); poll.Before(wake) {
				wake = poll
			}
		}
		time.Sleep(time.Until(wake))
	}
}

// pushLocal collects and pushes the agent's own machine. It returns
// whether the server asked the agent to rotate its credential.
func pushLocal(ctx context.Context, client *transport.Client, collect *snapshot.Collector, t target.Target, creds storedCredentials) bool {
	snap := collect.Collect(ctx, t)
	logCollectorErrors(t, snap)
	res, err := client.PushSnapshot(creds.AgentID, creds.AgentSecret, snap)
	if err != nil {
		log.Printf("[%s] push failed: %v", t.Ref(), err)
		return false
	}
	log.Printf("[%s] pushed snapshot: os=%s/%s, %d packages, %d listening sockets, %d services, %d users",
		t.Ref(), snap.Host.OSFamily, snap.OS.ID, len(snap.Packages), len(snap.ListeningSockets), len(snap.Services), len(snap.Users))
	return res.RotateCredentials
}

// Data directory: credentials.json and the ssh key. It must be a
// persistent, writable volume (docker: -v upkeep-agent-data:/var/lib/upkeep).
const (
	defaultDataDir = "/var/lib/upkeep"
	// legacyDataDir is where agents from before the rename kept their
	// credentials; still used when it holds them, so an upgraded agent
	// whose volume is mounted there doesn't re-enroll.
	legacyDataDir = "/var/lib/security-whatnot"
)

func resolveDataDir() string {
	if v := os.Getenv("SW_DATA_DIR"); v != "" {
		return v
	}
	if _, err := os.Stat(filepath.Join(legacyDataDir, "credentials.json")); err == nil {
		return legacyDataDir
	}
	return defaultDataDir
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
