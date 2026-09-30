// Command migrate applies the schema migrations embedded in the
// upkeep-server image (server/migrations) to DATABASE_URL and exits: 0 when
// the database is up to date (including when nothing was pending), non-zero
// on failure. Compose runs it as a one-shot service before api and worker,
// which refuse to start on an unmigrated database.
package main

import (
	"log"
	"os"
	"time"

	"github.com/pippinmole/upkeep.sh/server/migrations"
)

// version is the build version, set at build time with
// -ldflags "-X main.version=..." (server/Dockerfile's VERSION build arg).
var version = "dev"

// connectTimeout is how long to wait for Postgres to accept connections;
// it may still be starting when compose runs this.
const connectTimeout = 30 * time.Second

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}
	latest, err := migrations.Latest()
	if err != nil {
		log.Fatalf("read embedded migrations: %v", err)
	}

	var m *migrations.Migrator
	deadline := time.Now().Add(connectTimeout)
	for {
		m, err = migrations.New(dsn)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			log.Fatalf("connect to postgres: %v", err)
		}
		log.Printf("waiting for postgres: %v", err)
		time.Sleep(2 * time.Second)
	}
	defer m.Close()

	before, dirty, err := m.Version()
	if err != nil {
		log.Fatalf("read schema version: %v", err)
	}
	log.Printf("migrate %s: schema at version %d (dirty: %v), latest embedded %d", version, before, dirty, latest)

	if err := m.Up(); err != nil {
		m.Close()
		log.Fatalf("migrate: %v", err)
	}
	after, _, err := m.Version()
	if err != nil {
		m.Close()
		log.Fatalf("read schema version: %v", err)
	}
	if after == before {
		log.Printf("schema up to date at version %d", after)
	} else {
		log.Printf("migrated schema from version %d to %d", before, after)
	}
}
