// Command worker runs upkeep.sh background jobs on River: the OSV
// Debian/Ubuntu advisory sync (hourly incremental, weekly full), the CISA
// KEV and FIRST EPSS syncs (daily), the vulnerability matcher and findings
// reconciliation (see internal/jobs/matching.go).
//
//	worker                         run the River client until SIGINT/SIGTERM
//	worker sync osv Debian [-full] run one sync in the foreground and exit
//	worker sync kev | epss
//	worker match                   sweep stale versions + drain advisory_changes, then exit
//	worker reconcile [host-id...]  reconcile findings (all hosts by default), then exit
//	worker rerank                  recompute severity of every open finding, then exit
//
// The one-shot commands run the same code as the jobs, in the foreground;
// they are for operators and debugging (the scheduled jobs do all of this
// on their own).
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

	if len(os.Args) > 1 {
		var err error
		switch os.Args[1] {
		case "sync":
			err = runOnce(ctx, syncer, os.Args[2:])
		case "match":
			err = runMatch(ctx, db)
		case "reconcile":
			err = runReconcile(ctx, db, os.Args[2:])
		case "rerank":
			err = runRerank(ctx, db)
		default:
			log.Fatalf("unknown command %q (want no arguments, `sync`, `match`, `reconcile` or `rerank`)", os.Args[1])
		}
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	jcfg := jobs.Config{
		PeriodicSyncs:    envBool("SW_FEED_SYNC_ENABLED", true),
		OSVEcosystems:    strings.Split(envOr("SW_OSV_ECOSYSTEMS", strings.Join(feeds.OSVEcosystems, ",")), ","),
		OSVInterval:      envDuration("SW_OSV_SYNC_INTERVAL", time.Hour),
		CVEFeedsInterval: envDuration("SW_CVE_FEEDS_SYNC_INTERVAL", 24*time.Hour),
		FeedWorkers:      envInt("SW_FEED_JOB_WORKERS", 1),
		FindingsWorkers:  envInt("SW_FINDINGS_JOB_WORKERS", 4),
		MatcherInterval:  envDuration("SW_MATCHER_INTERVAL", 5*time.Minute),
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

// runMatch runs matcher_sweep then advisory_rematch synchronously and
// reconciles the hosts whose matches changed.
func runMatch(ctx context.Context, db *store.Store) error {
	sw, err := db.SweepStaleVersions(ctx)
	if err != nil {
		return err
	}
	log.Printf("sweep: %d versions evaluated in %.2fs, %d changed, %d matches", sw.Evaluated, sw.Seconds, len(sw.Changed), sw.Matches)
	dr, err := db.DrainAdvisoryChanges(ctx, store.DrainOptions{})
	if err != nil {
		return err
	}
	log.Printf("drain: %d keys in %.2fs (%d with versions, %d kept), %d versions evaluated, %d changed",
		dr.Keys, dr.Seconds, dr.KeysWithSW, dr.Kept, dr.Evaluated, len(dr.Changed))
	hosts, err := db.HostsWithSoftware(ctx, append(sw.Changed, dr.Changed...))
	if err != nil {
		return err
	}
	return runReconcile(ctx, db, hosts)
}

// runReconcile reconciles the given hosts, or every host when none given.
func runReconcile(ctx context.Context, db *store.Store, hosts []string) error {
	if len(hosts) == 0 && len(os.Args) > 1 && os.Args[1] == "reconcile" {
		rows, err := db.Pool.Query(ctx, `SELECT id::text FROM hosts ORDER BY id`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			hosts = append(hosts, id)
		}
		if err := rows.Err(); err != nil {
			return err
		}
	}
	for _, h := range hosts {
		start := time.Now()
		r, err := db.ReconcileHostFindings(ctx, h)
		if err != nil {
			return fmt.Errorf("host %s: %w", h, err)
		}
		log.Printf("reconcile %s in %.2fs: %d opened, %d reopened, %d resolved, %d unchanged (kernel %q)",
			h, time.Since(start).Seconds(), r.Opened, r.Reopened, r.Resolved, r.Kept, r.RunningKernel)
	}
	return nil
}

func runRerank(ctx context.Context, db *store.Store) error {
	r, err := db.RerankFindings(ctx, time.Time{})
	if err != nil {
		return err
	}
	log.Printf("rerank: %d open findings checked, %d updated", r.Checked, r.Updated)
	return nil
}
