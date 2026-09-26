// Command worker runs upkeep.sh background jobs on River: the OSV
// Debian/Ubuntu advisory sync (hourly incremental, weekly full), the CISA
// KEV and FIRST EPSS syncs (daily), and the matcher trigger.
//
//	worker                         run the River client until SIGINT/SIGTERM
//	worker sync osv Debian [-full] run one sync in the foreground and exit
//	worker sync kev | epss
//
// It is a separate process from cmd/api (same image, different
// entrypoint) so multi-minute, memory- and CPU-heavy feed imports never
// compete with agent ingest, and so the API stays a stateless HTTP server.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/feeds"
	"github.com/pippinmole/upkeep.sh/server/internal/jobs"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Fatalf("%s: %v", key, err)
	}
	return d
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("%s: %v", key, err)
	}
	return n
}

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		log.Fatalf("%s: %v", key, err)
	}
	return b
}

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}

	fcfg := feeds.DefaultConfig()
	fcfg.OSVBaseURL = envOr("SW_OSV_BASE_URL", fcfg.OSVBaseURL)
	if v := os.Getenv("SW_KEV_URL"); v != "" {
		fcfg.KEVURLs = strings.Split(v, ",") // comma-separated, tried in order
	}
	fcfg.EPSSURL = envOr("SW_EPSS_URL", fcfg.EPSSURL)
	fcfg.TmpDir = os.Getenv("SW_FEED_TMPDIR")
	fcfg.FullSyncInterval = envDuration("SW_OSV_FULL_SYNC_INTERVAL", fcfg.FullSyncInterval)
	fcfg.Workers = envInt("SW_OSV_PARSE_WORKERS", fcfg.Workers)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	openCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	db, err := store.Open(openCtx, dsn)
	cancel()
	if err != nil {
		log.Fatalf("connect to postgres: %v", err)
	}
	defer db.Close()

	syncer := &feeds.Syncer{
		Store: db,
		HTTP:  &http.Client{Timeout: 45 * time.Minute},
		Cfg:   fcfg,
	}

	if len(os.Args) > 1 && os.Args[1] == "sync" {
		if err := runOnce(ctx, syncer, os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) > 1 {
		log.Fatalf("unknown command %q (want no arguments, or `sync`)", os.Args[1])
	}

	jcfg := jobs.Config{
		PeriodicSyncs:    envBool("SW_FEED_SYNC_ENABLED", true),
		OSVEcosystems:    strings.Split(envOr("SW_OSV_ECOSYSTEMS", strings.Join(feeds.OSVEcosystems, ",")), ","),
		OSVInterval:      envDuration("SW_OSV_SYNC_INTERVAL", time.Hour),
		CVEFeedsInterval: envDuration("SW_CVE_FEEDS_SYNC_INTERVAL", 24*time.Hour),
		FeedWorkers:      envInt("SW_FEED_JOB_WORKERS", 1),
	}
	client, err := jobs.NewClient(db.Pool, db, syncer, jcfg)
	if err != nil {
		log.Fatalf("river client: %v", err)
	}
	if err := client.Start(ctx); err != nil {
		log.Fatalf("river start: %v", err)
	}
	log.Printf("worker started (periodic syncs: %v, osv ecosystems: %v, osv every %s, full every %s, kev/epss every %s)",
		jcfg.PeriodicSyncs, jcfg.OSVEcosystems, jcfg.OSVInterval, fcfg.FullSyncInterval, jcfg.CVEFeedsInterval)

	<-ctx.Done()
	log.Printf("shutting down: waiting up to 30s for running jobs")
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer stopCancel()
	if err := client.Stop(stopCtx); err != nil {
		// Jobs still running are cancelled; River retries them later.
		_ = client.StopAndCancel(context.Background())
	}
}

// runOnce runs a single sync synchronously and prints its stats as JSON.
func runOnce(ctx context.Context, s *feeds.Syncer, args []string) error {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	full := fs.Bool("full", false, "osv: force a full all.zip import")
	usage := "usage: worker sync osv <Debian|Ubuntu> [-full] | worker sync kev | worker sync epss"
	if len(args) == 0 {
		return fmt.Errorf("%s", usage)
	}
	var (
		stats any
		err   error
	)
	switch args[0] {
	case "osv":
		if len(args) < 2 {
			return fmt.Errorf("%s", usage)
		}
		_ = fs.Parse(args[2:])
		stats, err = s.SyncOSV(ctx, args[1], *full)
	case "kev":
		stats, err = s.SyncKEV(ctx)
	case "epss":
		stats, err = s.SyncEPSS(ctx)
	default:
		return fmt.Errorf("%s", usage)
	}
	b, _ := json.MarshalIndent(stats, "", "  ")
	fmt.Println(string(b))
	return err
}
