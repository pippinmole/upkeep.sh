package jobs

// Skipped unless SW_TEST_DATABASE_URL is set (see
// store/inventory_integration_test.go). Inserts jobs for a made-up
// ecosystem and deletes them afterwards; the client is never started.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/pippinmole/upkeep.sh/server/internal/feeds"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

func TestOSVSyncIsUniquePerEcosystem(t *testing.T) {
	dsn := os.Getenv("SW_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SW_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	eco := "swtest-" + hex.EncodeToString(b)
	t.Cleanup(func() {
		_, _ = s.Pool.Exec(context.Background(), `DELETE FROM river_job WHERE args->>'ecosystem' = $1`, eco)
	})

	client, err := NewClient(s.Pool, s, &feeds.Syncer{Store: s, Cfg: feeds.DefaultConfig()}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.Insert(ctx, OSVSyncArgs{Ecosystem: eco}, nil)
	if err != nil || first.UniqueSkippedAsDuplicate {
		t.Fatalf("first insert: %+v, %v", first, err)
	}
	// Same ecosystem, forced full: still a duplicate while the first waits.
	dup, err := client.Insert(ctx, OSVSyncArgs{Ecosystem: eco, Full: true}, nil)
	if err != nil || !dup.UniqueSkippedAsDuplicate {
		t.Fatalf("duplicate insert not skipped: %+v, %v", dup, err)
	}
	// Once the first completes, a new one may be inserted.
	if _, err := s.Pool.Exec(ctx, `UPDATE river_job SET state = 'completed', finalized_at = now() WHERE id = $1`, first.Job.ID); err != nil {
		t.Fatal(err)
	}
	again, err := client.Insert(ctx, OSVSyncArgs{Ecosystem: eco}, nil)
	if err != nil || again.UniqueSkippedAsDuplicate {
		t.Fatalf("insert after completion: %+v, %v", again, err)
	}
}
