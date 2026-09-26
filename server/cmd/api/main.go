// Command api is the security-whatnot ingest + platform API: agent
// enrollment and snapshot ingest. Background work (vulnerability matching,
// findings, feed syncs) runs in cmd/worker; ingest only enqueues it.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/ingest"
	"github.com/pippinmole/upkeep.sh/server/internal/jobs"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}
	addr := envOr("SW_LISTEN_ADDR", ":8080")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		log.Fatalf("connect to postgres: %v", err)
	}
	defer db.Close()

	// Insert-only River client: ingest enqueues matcher/findings jobs in the
	// snapshot transaction; cmd/worker runs them.
	inserter, err := jobs.NewInserter(db.Pool)
	if err != nil {
		log.Fatalf("river client: %v", err)
	}
	h := &ingest.Handler{Store: db, Jobs: inserter}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", h.Enroll)
	mux.HandleFunc("POST /v1/snapshots", h.Snapshot)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	go func() {
		log.Printf("api listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
}
