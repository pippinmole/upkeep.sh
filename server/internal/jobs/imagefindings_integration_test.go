package jobs

import (
	"context"
	"crypto/rand"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/feeds"
	"github.com/pippinmole/upkeep.sh/server/internal/inventory"
	"github.com/pippinmole/upkeep.sh/server/internal/notify"
	"github.com/pippinmole/upkeep.sh/server/internal/osv"
	"github.com/pippinmole/upkeep.sh/server/internal/purl"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

// The image job chain end to end, on River: a package list written with
// EnqueueAfterImageSBOM -> match_versions + reconcile_image (waits for the
// matcher, scores the list) -> reconcile_host for the host running the
// image -> vulnerable_image finding -> alert_events -> a rule selecting
// image findings -> notification carrying the image.
func TestImageFindingsPipeline(t *testing.T) {
	f := newAlertFixture(t)
	ctx := context.Background()
	fake := &fakeNotifier{}
	ch := f.channel("fake room", "fake", map[string]string{"room": "#sec"}, nil)
	rule := f.rule("images only", ruleOpts{types: []string{notify.EventFindingOpened}}, ch)
	f.exec(`UPDATE alert_rules SET finding_kinds = '{vulnerable_image}' WHERE id = $1`, rule)

	b := make([]byte, 3)
	_, _ = rand.Read(b)
	cve := fmt.Sprintf("CVE-1903-%d", 1000000+int(b[0])<<16|int(b[1])<<8|int(b[2]))
	f.cves = append(f.cves, cve)
	fixed, sev := "3.0.2-2", "high"
	if _, err := f.s.UpsertAdvisories(ctx, []osv.Advisory{{
		ID: "UBUNTU-" + cve, Source: f.tag, VulnKey: cve, CVEIDs: []string{cve}, Aliases: []string{},
		Upstream: []string{cve}, Related: []string{}, Modified: time.Now().UTC(), Raw: []byte(`{}`), ContentHash: f.tag,
		Affected: []osv.AffectedRow{{Distro: f.tag, Release: "jammy", SourcePackage: "openssl", Channel: osv.ChannelStandard,
			Introduced: "0", FixedVersion: &fixed, DistroSeverity: &sev, Status: "fixed", Ecosystem: "Test:22.04"}},
	}}); err != nil {
		t.Fatal(err)
	}

	key := store.ImageKey{ImageID: "sha256:" + f.tag, OS: "linux", Arch: "amd64"}
	f.exec(`INSERT INTO container_images (image_id, os, arch, variant) VALUES ($1, $2, $3, '')`, key.ImageID, key.OS, key.Arch)
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = f.s.Pool.Exec(ctx, `DELETE FROM host_containers WHERE host_id = $1`, f.hostID)
		_, _ = f.s.Pool.Exec(ctx, `DELETE FROM host_images WHERE host_id = $1`, f.hostID)
		_, _ = f.s.Pool.Exec(ctx, `DELETE FROM image_sbom_state WHERE image_id = $1`, key.ImageID)
		_, _ = f.s.Pool.Exec(ctx, `DELETE FROM container_images WHERE image_id = $1`, key.ImageID)
		_, _ = f.s.Pool.Exec(ctx, `DELETE FROM river_job WHERE args->>'image_id' = $1`, key.ImageID)
	})
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f.exec(`INSERT INTO host_images (host_id, image_id, repo_tags, os, arch, variant, row_key, row_hash, detail_hash, live_hash, first_seen_at)
	        VALUES ($1, $2, '{nginx:1.27}', 'linux', 'amd64', '', $2, 'h', 'd', 'l', $3)`, f.hostID, key.ImageID, t0)
	f.exec(`INSERT INTO host_containers (host_id, container_id, name, image_id, state, row_key, row_hash, detail_hash, live_hash, first_seen_at)
	        VALUES ($1, $2, 'web', $3, 'running', $2, 'h', 'd', 'l', $4)`, f.hostID, f.tag, key.ImageID, t0)

	client, err := NewClient(f.s.Pool, f.s, &feeds.Syncer{Store: f.s, Cfg: feeds.DefaultConfig()}, Config{
		DisableMatcherSchedule: true, DisableAlertSchedule: true,
		Alerting: AlertingConfig{Notifiers: notify.NewRegistry(fake), DashboardURL: "https://upkeep.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = client.Stop(stopCtx)
	})

	pkg := store.ImagePackage{Package: purl.Package{Ecosystem: "deb", Distro: f.tag, Release: "jammy", KnownType: true,
		Item: inventory.Item{Name: "libssl3", Version: "3.0.2-1", Arch: "amd64", Source: "openssl", SourceVersion: "3.0.2-1"}}}
	if _, err := f.s.WriteImageSBOM(ctx, store.ImageSBOMInput{
		Key: key, Source: store.SBOMSourceAttestation, Release: "jammy", Packages: []store.ImagePackage{pkg},
		AfterWrite: func(ctx context.Context, tx pgx.Tx, res store.ImageSBOMResult) error {
			return EnqueueAfterImageSBOM(ctx, client, tx, res)
		},
	}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(20 * time.Second)
	for len(fake.all()) < 1 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	got := fake.all()
	if len(got) != 1 || len(got[0].Events) != 1 {
		t.Fatalf("notifications: %+v", got)
	}
	ev := got[0].Events[0]
	if ev.Finding == nil || ev.Finding.Kind != "vulnerable_image" || ev.Finding.VulnKey != cve ||
		ev.Finding.ImageID != key.ImageID || !slices.Equal(ev.Finding.ImageRefs, []string{"nginx:1.27"}) ||
		!slices.Equal(ev.Finding.Containers, []string{"web"}) ||
		ev.URL != "https://upkeep.example/dashboard/images/-/"+key.ImageID+
			"?host="+f.hostID+"&q="+cve+"&tab=vulnerabilities" {
		t.Fatalf("image finding event: %+v / %+v", ev, ev.Finding)
	}
	sc, err := f.s.ImageScoreOf(ctx, f.workspaceID, key)
	if err != nil || sc == nil || !sc.Scored || *sc.Vulns != 1 || *sc.WorstSeverity != "high" {
		t.Fatalf("score after the chain: %+v %v", sc, err)
	}
}
