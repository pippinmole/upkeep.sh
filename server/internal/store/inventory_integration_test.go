package store

// Integration tests against a real, fully migrated Postgres. Skipped unless
// SW_TEST_DATABASE_URL is set, e.g. for the dev stack:
//
//	SW_TEST_DATABASE_URL=postgres://swuser:swpass@localhost:5432/security_whatnot?sslmode=disable go test ./...
//
// Each test creates its own user + host and interns versions under a
// unique distro name, and deletes all of it afterwards.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/inventory"
)

type fixture struct {
	t      *testing.T
	s      *Store
	hostID string
	distro string
	t0     time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dsn := os.Getenv("SW_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SW_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	tag := "swtest-" + hex.EncodeToString(b)

	f := &fixture{t: t, s: s, distro: tag, t0: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	var userID string
	if err := s.Pool.QueryRow(ctx, `INSERT INTO users (email) VALUES ($1) RETURNING id`,
		tag+"@test.invalid").Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if f.hostID, err = s.CreateHost(ctx, userID, tag); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = s.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID) // cascades host, snapshots, ranges
		_, _ = s.Pool.Exec(ctx, `DELETE FROM software_versions WHERE distro = $1`, tag)
		s.Close()
	})
	return f
}

func (f *fixture) set(items ...inventory.Item) inventory.Set {
	return inventory.NewSet("deb", f.distro, "jammy", items)
}

func pkg(name, version string) inventory.Item {
	return inventory.Item{Name: name, Version: version, Arch: "amd64", Source: name, SourceVersion: version}
}

// push inserts a snapshot collected at t0+minute with the given sets.
func (f *fixture) push(minute int, sets ...inventory.Set) SnapshotResult {
	f.t.Helper()
	at := f.t0.Add(time.Duration(minute) * time.Minute)
	res, err := f.s.InsertSnapshot(context.Background(), SnapshotInput{
		HostID: f.hostID, SchemaVersion: 1, CollectedAt: at, InventoryAt: at,
		OSID: f.distro, OSVersionID: "22.04", OSCodename: "jammy", Inventory: sets,
	})
	if err != nil {
		f.t.Fatalf("push at +%dm: %v", minute, err)
	}
	return res
}

type rangeRow struct {
	Name, Version  string
	First, Removed int // minutes after t0; -1 = open
}

func (f *fixture) ranges() []rangeRow {
	f.t.Helper()
	rows, err := f.s.Pool.Query(context.Background(), `
		SELECT sv.name, sv.version, hs.first_seen_at, hs.removed_at
		FROM host_software hs JOIN software_versions sv ON sv.id = hs.software_id
		WHERE hs.host_id = $1
		ORDER BY sv.name, sv.version, hs.first_seen_at`, f.hostID)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []rangeRow
	for rows.Next() {
		var r rangeRow
		var first time.Time
		var removed *time.Time
		if err := rows.Scan(&r.Name, &r.Version, &first, &removed); err != nil {
			f.t.Fatal(err)
		}
		r.First, r.Removed = int(first.Sub(f.t0).Minutes()), -1
		if removed != nil {
			r.Removed = int(removed.Sub(f.t0).Minutes())
		}
		out = append(out, r)
	}
	return out
}

func (f *fixture) wantRanges(want ...rangeRow) {
	f.t.Helper()
	if got := f.ranges(); !slices.Equal(got, want) {
		f.t.Fatalf("ranges:\n got  %v\n want %v", got, want)
	}
}

func outcome(t *testing.T, res SnapshotResult) InventoryResult {
	t.Helper()
	if len(res.Inventory) != 1 {
		t.Fatalf("want 1 inventory result, got %d", len(res.Inventory))
	}
	return res.Inventory[0]
}

func TestInventoryLifecycle(t *testing.T) {
	f := newFixture(t)

	r := outcome(t, f.push(1, f.set(pkg("a", "1"), pkg("b", "1"))))
	if r.Outcome != InventoryDiffed || r.Added != 2 || len(r.NewSoftwareIDs) != 2 {
		t.Fatalf("first push: %+v", r)
	}

	r = outcome(t, f.push(2, f.set(pkg("b", "1"), pkg("a", "1"))))
	if r.Outcome != InventoryUnchanged {
		t.Fatalf("same set should short-circuit: %+v", r)
	}

	// Upgrade a, add c.
	r = outcome(t, f.push(3, f.set(pkg("a", "2"), pkg("b", "1"), pkg("c", "1"))))
	if r.Outcome != InventoryDiffed || r.Added != 2 || r.Removed != 1 {
		t.Fatalf("upgrade: %+v", r)
	}

	// Collector failed: no set at all. Nothing may close.
	if res := f.push(4); len(res.Inventory) != 0 {
		t.Fatalf("no sets should mean no inventory work: %+v", res.Inventory)
	}

	// Out of order: collected before the newest applied inventory.
	r = outcome(t, f.push(0, f.set()))
	if r.Outcome != InventoryStale {
		t.Fatalf("stale push applied: %+v", r)
	}

	// Remove b, then reinstall it: a second range for the same version.
	f.push(5, f.set(pkg("a", "2"), pkg("c", "1")))
	f.push(6, f.set(pkg("a", "2"), pkg("b", "1"), pkg("c", "1")))

	f.wantRanges(
		rangeRow{"a", "1", 1, 3},
		rangeRow{"a", "2", 3, -1},
		rangeRow{"b", "1", 1, 5},
		rangeRow{"b", "1", 6, -1},
		rangeRow{"c", "1", 3, -1},
	)

	// Authoritative empty (collector ok, nothing installed) closes everything.
	r = outcome(t, f.push(7, f.set()))
	if r.Removed != 3 {
		t.Fatalf("empty set: %+v", r)
	}
	var open int
	_ = f.s.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM host_software WHERE host_id = $1 AND removed_at IS NULL`, f.hostID).Scan(&open)
	if open != 0 {
		t.Fatalf("%d ranges still open", open)
	}

	var hashes, schema string
	_ = f.s.Pool.QueryRow(context.Background(),
		`SELECT package_set_hashes::text, schema_version::text FROM snapshots
		 WHERE host_id = $1 ORDER BY collected_at DESC LIMIT 1`, f.hostID).Scan(&hashes, &schema)
	if hashes != `{"deb": "`+f.set().Hash+`"}` || schema != "1" {
		t.Fatalf("snapshot bookkeeping: hashes=%s schema=%s", hashes, schema)
	}
}

func TestInferredSourceIsUpgraded(t *testing.T) {
	f := newFixture(t)
	inferred := inventory.Item{Name: "libssl3", Version: "3.0.2", Arch: "amd64",
		Source: "libssl3", SourceVersion: "3.0.2", SourceInferred: true}
	real := inventory.Item{Name: "libssl3", Version: "3.0.2", Arch: "amd64",
		Source: "openssl", SourceVersion: "3.0.2"}

	f.push(1, f.set(inferred))
	r := outcome(t, f.push(2, f.set(real)))
	// Hash differs (source changed) so a diff runs, but it is the same
	// interned version: no range churn.
	if r.Outcome != InventoryDiffed || r.Added != 0 || r.Removed != 0 {
		t.Fatalf("source upgrade churned ranges: %+v", r)
	}
	var src string
	var inf bool
	_ = f.s.Pool.QueryRow(context.Background(),
		`SELECT source_name, source_inferred FROM software_versions WHERE distro = $1`, f.distro).Scan(&src, &inf)
	if src != "openssl" || inf {
		t.Fatalf("source not upgraded: %s inferred=%v", src, inf)
	}
	// An inferred report must never downgrade a real source.
	f.push(3, f.set(inferred))
	_ = f.s.Pool.QueryRow(context.Background(),
		`SELECT source_name FROM software_versions WHERE distro = $1`, f.distro).Scan(&src)
	if src != "openssl" {
		t.Fatalf("real source overwritten by inferred: %s", src)
	}
}

func TestConcurrentPushesSerialise(t *testing.T) {
	f := newFixture(t)
	f.push(1, f.set(pkg("a", "1")))

	// Rounds of concurrent pushes with distinct timestamps and alternating
	// sets. Serialised by the host lock, each sees a consistent previous
	// state; without it, a push can close or open ranges from a stale read
	// and leave the stored hash describing a different set than the open
	// ranges (this test fails within a few rounds if the lock is removed).
	ctx := context.Background()
	for round := range 8 {
		base := 10 + round*100
		var wg sync.WaitGroup
		errs := make(chan error, 20)
		for i := range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				set := f.set(pkg("a", "1"), pkg("x", "1"))
				if i%2 == 1 {
					set = f.set(pkg("a", "2"))
				}
				at := f.t0.Add(time.Duration(base+i) * time.Minute)
				_, err := f.s.InsertSnapshot(ctx, SnapshotInput{
					HostID: f.hostID, SchemaVersion: 1, CollectedAt: at, InventoryAt: at,
					OSID: f.distro, OSCodename: "jammy", Inventory: []inventory.Set{set},
				})
				errs <- err
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		}

		// Whatever order they committed in, the open ranges must equal the
		// set of the push with the newest applied boundary, and the stored
		// hash must describe exactly that set.
		var hash string
		var confirmed time.Time
		if err := f.s.Pool.QueryRow(ctx, `SELECT package_set_hash, confirmed_at FROM host_inventory_state
			WHERE host_id = $1 AND ecosystem = 'deb'`, f.hostID).Scan(&hash, &confirmed); err != nil {
			t.Fatal(err)
		}
		i := int(confirmed.Sub(f.t0).Minutes()) - base
		want := []string{"a/1", "x/1"}
		wantHash := f.set(pkg("a", "1"), pkg("x", "1")).Hash
		if i%2 == 1 {
			want, wantHash = []string{"a/2"}, f.set(pkg("a", "2")).Hash
		}
		rows, _ := f.s.Pool.Query(ctx, `SELECT sv.name || '/' || sv.version FROM host_software hs
			JOIN software_versions sv ON sv.id = hs.software_id
			WHERE hs.host_id = $1 AND hs.removed_at IS NULL ORDER BY 1`, f.hostID)
		var got []string
		for rows.Next() {
			var s string
			_ = rows.Scan(&s)
			got = append(got, s)
		}
		rows.Close()
		if !slices.Equal(got, want) || hash != wantHash {
			t.Fatalf("round %d: open=%v want %v (hash match=%v)", round, got, want, hash == wantHash)
		}
	}
}
