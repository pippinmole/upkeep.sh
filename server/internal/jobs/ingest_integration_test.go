package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/inventory"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

// Ingest enqueues match_versions + reconcile_host in the snapshot
// transaction: committed together, rolled back together.
func TestEnqueueAfterIngestIsTransactional(t *testing.T) {
	dsn := os.Getenv("SW_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SW_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close) // registered first, so it runs after the cleanups below (LIFO)
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	tag := "swtest-" + hex.EncodeToString(b)
	var workspaceID string
	if err := s.Pool.QueryRow(ctx, `INSERT INTO workspaces (name) VALUES ($1) RETURNING id`,
		tag+"@test.invalid").Scan(&workspaceID); err != nil {
		t.Fatal(err)
	}
	hostID, err := s.CreateHost(ctx, workspaceID, tag)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = s.Pool.Exec(ctx, `DELETE FROM river_job WHERE args->>'host_id' = $1 OR kind = 'match_versions' AND args->'ids' @> (
			SELECT to_jsonb(array_agg(id)) FROM software_versions WHERE distro = $2)`, hostID, tag)
		_, _ = s.Pool.Exec(ctx, `DELETE FROM workspaces WHERE id = $1`, workspaceID)
		_, _ = s.Pool.Exec(ctx, `DELETE FROM software_versions WHERE distro = $1`, tag)
	})
	client, err := NewInserter(s.Pool)
	if err != nil {
		t.Fatal(err)
	}
	jobCount := func() (match, reconcile int) {
		_ = s.Pool.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE kind = 'reconcile_host'),
			       count(*) FILTER (WHERE kind = 'match_versions' AND jsonb_array_length(args->'ids') = 2
			                        AND EXISTS (SELECT 1 FROM software_versions sv
			                                    WHERE sv.distro = $2 AND (args->'ids') @> to_jsonb(sv.id)))
			FROM river_job WHERE args->>'host_id' = $1 OR kind = 'match_versions'`, hostID, tag).Scan(&reconcile, &match)
		return
	}
	set := inventory.NewSet("deb", tag, "jammy", []inventory.Item{
		{Name: "a", Version: "1", Arch: "amd64", Source: "a", SourceVersion: "1"},
		{Name: "b", Version: "1", Arch: "amd64", Source: "b", SourceVersion: "1"},
	})
	push := func(minute int, fail bool) error {
		at := time.Date(2026, 1, 1, 0, minute, 0, 0, time.UTC)
		_, err := s.InsertSnapshot(ctx, store.SnapshotInput{
			HostID: hostID, SchemaVersion: 1, CollectedAt: at, InventoryAt: at, OSID: tag, OSCodename: "jammy",
			Inventory: []inventory.Set{set},
			AfterWrite: func(ctx context.Context, tx pgx.Tx, res store.SnapshotResult) error {
				if err := EnqueueAfterIngest(ctx, client, tx, hostID, res); err != nil {
					return err
				}
				if fail {
					return errors.New("injected")
				}
				return nil
			},
		})
		return err
	}

	if err := push(1, true); err == nil {
		t.Fatal("injected failure did not fail the push")
	}
	if m, r := jobCount(); m != 0 || r != 0 {
		t.Fatalf("rolled-back push left jobs: match %d, reconcile %d", m, r)
	}
	if err := push(2, false); err != nil {
		t.Fatal(err)
	}
	if m, r := jobCount(); m != 1 || r != 1 {
		t.Fatalf("committed push: match %d, reconcile %d; want 1, 1", m, r)
	}
	// Unchanged inventory, unknown kernel as before: nothing to enqueue.
	if err := push(3, false); err != nil {
		t.Fatal(err)
	}
	if m, r := jobCount(); m != 1 || r != 1 {
		t.Fatalf("unchanged push enqueued work: match %d, reconcile %d", m, r)
	}
}
