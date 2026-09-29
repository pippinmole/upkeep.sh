package jobs

// Alerting integration tests against a real, fully migrated Postgres;
// skipped unless SW_TEST_DATABASE_URL is set. Every test in this file
// evaluates the global alert_events outbox, so they are sequential (no
// t.Parallel) and live in one package; other packages' tests write no
// alert events (their users have no rules).
//
// Use a database of your own: TestAlertPipelineEndToEnd starts a River
// client that works every queued job.

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/pippinmole/upkeep.sh/server/internal/feeds"
	"github.com/pippinmole/upkeep.sh/server/internal/findings"
	"github.com/pippinmole/upkeep.sh/server/internal/inventory"
	"github.com/pippinmole/upkeep.sh/server/internal/netguard"
	"github.com/pippinmole/upkeep.sh/server/internal/notify"
	"github.com/pippinmole/upkeep.sh/server/internal/notify/webhook"
	"github.com/pippinmole/upkeep.sh/server/internal/osv"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

// fakeNotifier is a channel type the dispatcher has never heard of: it is
// registered next to the webhook and must work with no other change
// (extensibility of internal/notify).
type fakeNotifier struct {
	mu   sync.Mutex
	got  []notify.Notification
	cfgs []notify.Config
	err  error // returned by Send when set
}

func (f *fakeNotifier) Spec() notify.Spec {
	return notify.Spec{Type: "fake", Label: "Fake", Fields: []notify.Field{
		{Key: "room", Label: "Room", Type: notify.FieldText, Required: true},
		{Key: "token", Label: "Token", Type: notify.FieldSecret, Secret: true},
	}}
}
func (f *fakeNotifier) Validate(cfg notify.Config) error {
	return notify.ValidateRequired(f.Spec(), cfg)
}
func (f *fakeNotifier) Send(_ context.Context, cfg notify.Config, n notify.Notification) (notify.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.Validate(cfg); err != nil {
		return notify.Result{}, notify.Permanent(err)
	}
	if f.err != nil {
		return notify.Result{StatusCode: 503}, f.err
	}
	f.got = append(f.got, n)
	f.cfgs = append(f.cfgs, cfg)
	return notify.Result{StatusCode: 200}, nil
}
func (f *fakeNotifier) all() []notify.Notification {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]notify.Notification(nil), f.got...)
}

type alertFixture struct {
	t      *testing.T
	s      *store.Store
	tag    string
	userID string
	hostID string
	cves   []string
}

func newAlertFixture(t *testing.T) *alertFixture {
	t.Helper()
	dsn := os.Getenv("SW_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SW_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	f := &alertFixture{t: t, s: s, tag: "swtest-" + hex.EncodeToString(b)}
	if err := s.Pool.QueryRow(ctx, `INSERT INTO users (email) VALUES ($1) RETURNING id`,
		f.tag+"@test.invalid").Scan(&f.userID); err != nil {
		t.Fatal(err)
	}
	if f.hostID, err = s.CreateHost(ctx, f.userID, "web-"+f.tag); err != nil {
		t.Fatal(err)
	}
	// Anything still pending in the outbox belongs to an earlier, aborted
	// run: mark it processed so it can't leak into this test's counts.
	_, _ = s.Pool.Exec(ctx, `UPDATE alert_events SET processed_at = now() WHERE processed_at IS NULL`)
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = s.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, f.userID)
		_, _ = s.Pool.Exec(ctx, `DELETE FROM software_versions WHERE distro = $1`, f.tag)
		_, _ = s.Pool.Exec(ctx, `DELETE FROM advisories WHERE source = $1`, f.tag)
		_, _ = s.Pool.Exec(ctx, `DELETE FROM advisory_changes WHERE distro = $1`, f.tag)
		_, _ = s.Pool.Exec(ctx, `DELETE FROM cves WHERE id = ANY ($1)`, f.cves)
		_, _ = s.Pool.Exec(ctx, `DELETE FROM river_job WHERE args->>'host_id' = $1`, f.hostID)
		s.Close()
	})
	return f
}

func (f *alertFixture) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.s.Pool.Exec(context.Background(), q, args...); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
}

func (f *alertFixture) channel(name, typ string, config, secrets map[string]string) string {
	f.t.Helper()
	c, _ := json.Marshal(config)
	s, _ := json.Marshal(secrets)
	var id string
	if err := f.s.Pool.QueryRow(context.Background(), `
		INSERT INTO notification_channels (user_id, name, type, config, secrets) VALUES ($1, $2, $3, $4, $5) RETURNING id
	`, f.userID, name, typ, c, s).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	return id
}

type ruleOpts struct {
	types       []string
	minSeverity int
	kevOnly     bool
	hostIDs     []string
	dedup       time.Duration
	digest      time.Duration // > 0: digest mode
	createdAt   time.Time
}

func (f *alertFixture) rule(name string, o ruleOpts, channels ...string) string {
	f.t.Helper()
	if o.createdAt.IsZero() {
		o.createdAt = time.Now()
	}
	interval := 3600
	if o.digest > 0 {
		interval = int(o.digest.Seconds())
	}
	var id string
	if err := f.s.Pool.QueryRow(context.Background(), `
		INSERT INTO alert_rules (user_id, name, event_types, min_severity_rank, kev_only, host_ids,
		                         dedup_window_seconds, digest, digest_interval_seconds, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id
	`, f.userID, name, o.types, o.minSeverity, o.kevOnly, o.hostIDs, int(o.dedup.Seconds()),
		o.digest > 0, interval, o.createdAt).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	for _, c := range channels {
		f.exec(`INSERT INTO alert_rule_channels (rule_id, channel_id, user_id) VALUES ($1, $2, $3)`, id, c, f.userID)
	}
	return id
}

// event inserts an alert_events row for the fixture's user directly.
func (f *alertFixture) event(typ, subject string, sevRank *int, kev bool, at time.Time) {
	f.t.Helper()
	payload := fmt.Sprintf(`{"host":{"id":%q,"hostname":"web"},"finding":{"id":"00000000-0000-0000-0000-000000000000","kind":"vulnerable_package","vuln_key":%q,"severity":"high","severity_rank":5,"kev":%v,"status":"open"}}`,
		f.hostID, subject, kev)
	f.exec(`INSERT INTO alert_events (user_id, type, subject, occurred_at, host_ids, severity_rank, is_kev, payload)
	        VALUES ($1, $2, $3, $4, ARRAY[$5::uuid], $6, $7, $8)`, f.userID, typ, subject, at, f.hostID, sevRank, kev, payload)
}

func (f *alertFixture) count(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.s.Pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
	return n
}

// ---- End to end: reconcile transition -> outbox -> rule -> signed webhook ----

type received struct {
	body    []byte
	headers http.Header
}

func TestAlertPipelineEndToEnd(t *testing.T) {
	f := newAlertFixture(t)
	ctx := context.Background()

	hooks := make(chan received, 10)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		hooks <- received{b, r.Header.Clone()}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	// httptest listens on loopback: the dev escape hatch is required, and
	// the production guard would refuse it (see netguard tests).
	guard := &netguard.Guard{AllowPrivate: true, TLSConfig: &tls.Config{RootCAs: pool}}
	fake := &fakeNotifier{}
	registry := notify.NewRegistry(webhook.New(guard), fake)

	const secret = "whsec_integration"
	hook := f.channel("ops webhook", "webhook", map[string]string{"url": srv.URL + "/hook"}, map[string]string{"secret": secret})
	fakeCh := f.channel("fake room", "fake", map[string]string{"room": "#sec"}, map[string]string{"token": "t0k"})
	ruleID := f.rule("High and up", ruleOpts{
		types:       []string{notify.EventFindingOpened, notify.EventFindingResolved},
		minSeverity: 5, hostIDs: []string{f.hostID}, dedup: time.Hour,
	}, hook, fakeCh)

	// Advisory: swlib fixed in 1.0-2, high.
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	cve := fmt.Sprintf("CVE-1902-%d", 1000000+int(b[0])<<16|int(b[1])<<8|int(b[2]))
	f.cves = append(f.cves, cve)
	fixed, sev := "1.0-2", "high"
	if _, err := f.s.UpsertAdvisories(ctx, []osv.Advisory{{
		ID: "UBUNTU-" + cve, Source: f.tag, VulnKey: cve, CVEIDs: []string{cve}, Aliases: []string{},
		Upstream: []string{cve}, Related: []string{}, Modified: time.Now().UTC(), Raw: []byte(`{}`), ContentHash: f.tag,
		Affected: []osv.AffectedRow{{Distro: f.tag, Release: "jammy", SourcePackage: "swlib", Channel: osv.ChannelStandard,
			Introduced: "0", FixedVersion: &fixed, DistroSeverity: &sev, Status: "fixed", Ecosystem: "Test:22.04"}},
	}}); err != nil {
		t.Fatal(err)
	}
	push := func(minute int, version string) {
		t.Helper()
		at := time.Date(2026, 1, 1, 0, minute, 0, 0, time.UTC)
		res, err := f.s.InsertSnapshot(ctx, store.SnapshotInput{
			HostID: f.hostID, SchemaVersion: 1, CollectedAt: at, InventoryAt: at,
			OSID: f.tag, OSVersionID: "22.04", OSCodename: "jammy",
			Inventory: []inventory.Set{inventory.NewSet("deb", f.tag, "jammy", []inventory.Item{
				{Name: "libsw1", Version: version, Arch: "amd64", Source: "swlib", SourceVersion: version}})},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.MatchVersions(ctx, res.RematchSoftwareIDs()); err != nil {
			t.Fatal(err)
		}
	}

	client, err := NewClient(f.s.Pool, f.s, &feeds.Syncer{Store: f.s, Cfg: feeds.DefaultConfig()}, Config{
		DisableMatcherSchedule: true, DisableAlertSchedule: true,
		Alerting: AlertingConfig{Notifiers: registry, DashboardURL: "https://upkeep.example"},
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

	await := func(wantType string) notify.Notification {
		t.Helper()
		select {
		case r := <-hooks:
			if err := webhook.Verify(secret, r.headers.Get(webhook.HeaderSignature), r.headers.Get(webhook.HeaderTimestamp),
				r.body, time.Now(), 5*time.Minute); err != nil {
				t.Fatalf("signature does not verify: %v", err)
			}
			var n notify.Notification
			if err := json.Unmarshal(r.body, &n); err != nil {
				t.Fatal(err)
			}
			if r.headers.Get(webhook.HeaderDelivery) != n.DeliveryID || n.DeliveryID == "" {
				t.Fatalf("delivery id header %q vs body %q", r.headers.Get(webhook.HeaderDelivery), n.DeliveryID)
			}
			if len(n.Events) != 1 || n.Events[0].Type != wantType {
				t.Fatalf("want one %s event, got %s", wantType, r.body)
			}
			return n
		case <-time.After(20 * time.Second):
			t.Fatalf("no %s webhook received", wantType)
		}
		return notify.Notification{}
	}

	// 1. Vulnerable version installed -> finding opened -> webhook.
	push(1, "1.0-1")
	if _, err := client.Insert(ctx, ReconcileHostArgs{HostID: f.hostID}, nil); err != nil {
		t.Fatal(err)
	}
	n := await(notify.EventFindingOpened)
	ev := n.Events[0]
	if n.Kind != notify.KindAlert || n.Rule == nil || n.Rule.ID != ruleID || n.Version != 1 ||
		ev.Finding == nil || ev.Finding.VulnKey != cve || ev.Finding.Severity != "high" || ev.Finding.Status != "open" ||
		ev.Host == nil || ev.Host.ID != f.hostID ||
		ev.URL != "https://upkeep.example/dashboard/hosts/"+f.hostID+"/vulnerabilities?v="+cve {
		t.Fatalf("opened notification: %+v / %+v", n, ev)
	}

	// 2. Upgrade to the fixed version -> resolved -> webhook.
	push(2, "1.0-2")
	if _, err := client.Insert(ctx, ReconcileHostArgs{HostID: f.hostID}, nil); err != nil {
		t.Fatal(err)
	}
	n = await(notify.EventFindingResolved)
	if n.Events[0].Finding.Status != "resolved" {
		t.Fatalf("resolved event: %+v", n.Events[0].Finding)
	}

	// The fake channel type got both, with its secret merged into config.
	deadline := time.Now().Add(10 * time.Second)
	for len(fake.all()) < 2 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	got := fake.all()
	if len(got) != 2 || got[0].Events[0].Type != notify.EventFindingOpened || fake.cfgs[0]["token"] != "t0k" || fake.cfgs[0]["room"] != "#sec" {
		t.Fatalf("fake notifier: %d notifications, cfg %v", len(got), fake.cfgs)
	}
	// Delivery log: 4 delivered deliveries, one attempt each.
	for time.Now().Before(deadline) && f.count(`SELECT count(*) FROM notification_deliveries WHERE user_id = $1 AND status = 'delivered'`, f.userID) < 4 {
		time.Sleep(100 * time.Millisecond)
	}
	if n := f.count(`SELECT count(*) FROM notification_deliveries WHERE user_id = $1 AND status = 'delivered' AND attempts = 1 AND delivered_at IS NOT NULL`, f.userID); n != 4 {
		t.Fatalf("delivered deliveries = %d, want 4", n)
	}
	if n := f.count(`SELECT count(*) FROM notification_delivery_attempts a JOIN notification_deliveries d ON d.id = a.delivery_id
	                 WHERE d.user_id = $1 AND d.channel_type = 'webhook' AND a.status_code = 204`, f.userID); n != 2 {
		t.Fatalf("webhook attempts with 204 = %d, want 2", n)
	}
}

// ---- Rule matching, dedup and digests at the store level ----

func TestEvaluateDedupAndDigest(t *testing.T) {
	f := newAlertFixture(t)
	ctx := context.Background()
	ch := f.channel("fake", "fake", map[string]string{"room": "r"}, nil)
	immediate := f.rule("immediate", ruleOpts{types: []string{notify.EventFindingOpened}, minSeverity: 4, dedup: time.Hour}, ch)
	t0 := time.Now().UTC().Truncate(time.Second)
	digest := f.rule("digest", ruleOpts{types: []string{notify.EventFindingOpened, notify.EventFindingResolved},
		digest: time.Hour, dedup: 0, createdAt: t0.Add(-2 * time.Hour)}, ch)
	// A rule without channels matches nothing (nothing could be sent).
	f.rule("no channels", ruleOpts{types: []string{notify.EventFindingOpened}})

	var enqueued []string
	opt := store.AlertOptions{Enqueue: func(_ context.Context, _ pgx.Tx, ids []string) error {
		enqueued = append(enqueued, ids...)
		return nil
	}}
	eval := func(at time.Time) store.EvalResult {
		t.Helper()
		r, err := f.s.EvaluateAlerts(ctx, at, opt)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	high, low := 5, 2
	f.event(notify.EventFindingOpened, "finding:a", &high, false, t0)
	f.event(notify.EventFindingOpened, "finding:a", &high, false, t0) // duplicate in the same batch
	f.event(notify.EventFindingOpened, "finding:b", &high, true, t0)
	f.event(notify.EventFindingOpened, "finding:low", &low, false, t0) // below the immediate rule's floor
	r := eval(t0)
	// immediate: a, b (a's duplicate suppressed, low filtered); digest: all 4 (no dedup window)
	if r.Events != 4 || r.Suppressed != 1 || r.Digested != 4 || r.Notifications != 1 || r.Deliveries != 1 || len(enqueued) != 1 {
		t.Fatalf("first pass: %+v, enqueued %d", r, len(enqueued))
	}
	var payload []byte
	if err := f.s.Pool.QueryRow(ctx, `SELECT payload FROM notifications WHERE rule_id = $1`, immediate).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var n notify.Notification
	_ = json.Unmarshal(payload, &n)
	if len(n.Events) != 2 || n.Kind != notify.KindAlert || n.Summary == "" {
		t.Fatalf("immediate notification: %s", payload)
	}

	// Same subject again inside the window: suppressed; after it: sent.
	f.event(notify.EventFindingOpened, "finding:a", &high, false, t0.Add(30*time.Minute))
	if r := eval(t0.Add(30 * time.Minute)); r.Suppressed != 1 || r.Notifications != 0 {
		t.Fatalf("inside window: %+v", r)
	}
	f.event(notify.EventFindingOpened, "finding:a", &high, false, t0.Add(61*time.Minute))
	if r := eval(t0.Add(61 * time.Minute)); r.Suppressed != 0 || r.Notifications != 1 {
		t.Fatalf("after window: %+v", r)
	}
	// A different event type about the same subject is not a duplicate.
	f.event(notify.EventFindingResolved, "finding:a", &high, false, t0.Add(62*time.Minute))
	if r := eval(t0.Add(62 * time.Minute)); r.Suppressed != 0 || r.Digested != 1 {
		t.Fatalf("resolved: %+v", r)
	}

	// Digest: the rule was created 2h ago, so the first flush is due; all
	// seven items (4 + a@30m + a@61m + resolved) go in one notification.
	flush := func(at time.Time) store.DigestResult {
		t.Helper()
		d, err := f.s.FlushDigests(ctx, at, opt)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	d := flush(t0.Add(63 * time.Minute))
	if d.Rules != 1 || d.Events != 7 || d.Notifications != 1 || d.Deliveries != 1 {
		t.Fatalf("first digest: %+v", d)
	}
	if err := f.s.Pool.QueryRow(ctx, `SELECT payload FROM notifications WHERE rule_id = $1 AND kind = 'digest'`, digest).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(payload, &n)
	if len(n.Events) != 7 || n.Rule.Name != "digest" || n.Events[0].ID > n.Events[6].ID {
		t.Fatalf("digest notification: %d events", len(n.Events))
	}
	// A new item right after: not due until an hour after the last digest.
	f.event(notify.EventFindingOpened, "finding:c", &high, false, t0.Add(64*time.Minute))
	eval(t0.Add(64 * time.Minute))
	if d := flush(t0.Add(90 * time.Minute)); d.Rules != 0 {
		t.Fatalf("digest before interval: %+v", d)
	}
	if d := flush(t0.Add(124 * time.Minute)); d.Rules != 1 || d.Events != 1 {
		t.Fatalf("second digest: %+v", d)
	}
	// Disabled rule: pending items are dropped, not sent.
	f.event(notify.EventFindingOpened, "finding:d", &high, false, t0.Add(125*time.Minute))
	eval(t0.Add(125 * time.Minute))
	f.exec(`UPDATE alert_rules SET enabled = false WHERE id = $1`, digest)
	if d := flush(t0.Add(300 * time.Minute)); d.Rules != 0 {
		t.Fatalf("disabled digest rule flushed: %+v", d)
	}
	if n := f.count(`SELECT count(*) FROM alert_digest_items WHERE rule_id = $1`, digest); n != 0 {
		t.Fatalf("disabled rule kept %d items", n)
	}
}

// Host scope and KEV-only at the store level (Match is unit-tested; this
// checks the SQL feeds it the right host ids and flags).
func TestEvaluateScopeAndKEV(t *testing.T) {
	f := newAlertFixture(t)
	ctx := context.Background()
	other, err := f.s.CreateHost(ctx, f.userID, "other-"+f.tag)
	if err != nil {
		t.Fatal(err)
	}
	ch := f.channel("fake", "fake", map[string]string{"room": "r"}, nil)
	f.rule("kev on other host", ruleOpts{types: []string{notify.EventFindingOpened}, kevOnly: true, hostIDs: []string{other}}, ch)
	sev := 6
	now := time.Now().UTC()
	f.event(notify.EventFindingOpened, "finding:kev-on-fixture-host", &sev, true, now) // wrong host
	r, err := f.s.EvaluateAlerts(ctx, now, store.AlertOptions{})
	if err != nil || r.Matched != 0 {
		t.Fatalf("out of scope: %+v %v", r, err)
	}
	f.exec(`INSERT INTO alert_events (user_id, type, subject, host_ids, severity_rank, is_kev, payload)
	        VALUES ($1, 'finding.opened', 's1', ARRAY[$2::uuid], 6, false, '{}'), ($1, 'finding.opened', 's2', ARRAY[$2::uuid], 6, true, '{}')`,
		f.userID, other)
	if r, err = f.s.EvaluateAlerts(ctx, now, store.AlertOptions{}); err != nil || r.Matched != 1 || r.Notifications != 1 {
		t.Fatalf("in scope: %+v %v", r, err)
	}
}

// alert_rules.finding_kinds (migration 0015): a rule created without it
// gets both kinds; a narrowed rule only sees events of its kinds.
func TestEvaluateFindingKinds(t *testing.T) {
	f := newAlertFixture(t)
	ctx := context.Background()
	ch := f.channel("fake", "fake", map[string]string{"room": "r"}, nil)
	both := f.rule("both", ruleOpts{types: []string{notify.EventFindingOpened}}, ch)
	images := f.rule("images", ruleOpts{types: []string{notify.EventFindingOpened}}, ch)
	pkgs := f.rule("packages", ruleOpts{types: []string{notify.EventFindingOpened}}, ch)
	f.exec(`UPDATE alert_rules SET finding_kinds = '{vulnerable_image}' WHERE id = $1`, images)
	f.exec(`UPDATE alert_rules SET finding_kinds = '{vulnerable_package}' WHERE id = $1`, pkgs)
	var kinds []string
	if err := f.s.Pool.QueryRow(ctx, `SELECT finding_kinds FROM alert_rules WHERE id = $1`, both).Scan(&kinds); err != nil ||
		len(kinds) != 2 {
		t.Fatalf("default finding_kinds = %v (%v), want both", kinds, err)
	}
	for _, bad := range []string{`'{}'`, `'{public_port}'`} {
		if _, err := f.s.Pool.Exec(ctx, `UPDATE alert_rules SET finding_kinds = `+bad+` WHERE id = $1`, both); err == nil {
			t.Errorf("finding_kinds = %s accepted", bad)
		}
	}

	sev := 5
	now := time.Now().UTC()
	f.event(notify.EventFindingOpened, "finding:pkg", &sev, false, now) // kind vulnerable_package
	f.exec(`INSERT INTO alert_events (user_id, type, subject, host_ids, severity_rank, is_kev, payload)
	        VALUES ($1, 'finding.opened', 'finding:img', ARRAY[$2::uuid], 5, false,
	                '{"finding": {"kind": "vulnerable_image", "vuln_key": "CVE-1", "image_id": "sha256:x", "severity": "high"}}')`,
		f.userID, f.hostID)
	r, err := f.s.EvaluateAlerts(ctx, now, store.AlertOptions{})
	if err != nil || r.Events != 2 || r.Matched != 4 {
		t.Fatalf("evaluate: %+v %v (want 2 events, 4 matches)", r, err)
	}
	for id, want := range map[string]int{both: 2, images: 1, pkgs: 1} {
		if n := f.count(`SELECT coalesce(sum(event_count), 0) FROM notifications WHERE rule_id = $1`, id); n != want {
			t.Errorf("rule %s: %d events notified, want %d", id, n, want)
		}
	}
}

// Outbox writes only happen for users with a matching enabled rule, and
// reconcile's hook sees how many were written.
func TestAgentHealthEvents(t *testing.T) {
	f := newAlertFixture(t)
	ctx := context.Background()
	ch := f.channel("fake", "fake", map[string]string{"room": "r"}, nil)
	f.rule("agents", ruleOpts{types: []string{notify.EventAgentStale, notify.EventAgentRecovered}}, ch)
	now := time.Now().UTC().Truncate(time.Second)
	var agentID string
	if err := f.s.Pool.QueryRow(ctx, `
		INSERT INTO agents (user_id, name, push_interval_seconds, last_seen_at) VALUES ($1, $2, 60, $3) RETURNING id
	`, f.userID, "agent-"+f.tag, now).Scan(&agentID); err != nil {
		t.Fatal(err)
	}
	f.exec(`INSERT INTO agent_hosts (agent_id, host_id, mode) VALUES ($1, $2, 'local')`, agentID, f.hostID)
	events := func() []string {
		rows, err := f.s.Pool.Query(ctx, `SELECT type FROM alert_events WHERE subject = $1 ORDER BY id`, "agent:"+agentID)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for rows.Next() {
			var s string
			_ = rows.Scan(&s)
			out = append(out, s)
		}
		return out
	}
	check := func(at time.Time) {
		t.Helper()
		if _, err := f.s.CheckAgentHealth(ctx, at); err != nil {
			t.Fatal(err)
		}
	}
	check(now) // first observation: recorded silently
	if e := events(); len(e) != 0 {
		t.Fatalf("first observation emitted %v", e)
	}
	check(now.Add(2 * time.Minute)) // threshold max(3*60, 120) = 180s: still online
	check(now.Add(4 * time.Minute)) // stale
	check(now.Add(5 * time.Minute)) // still stale: no new event
	if e := events(); len(e) != 1 || e[0] != notify.EventAgentStale {
		t.Fatalf("after going stale: %v", e)
	}
	f.exec(`UPDATE agents SET last_seen_at = $2 WHERE id = $1`, agentID, now.Add(6*time.Minute))
	check(now.Add(6 * time.Minute))
	if e := events(); len(e) != 2 || e[1] != notify.EventAgentRecovered {
		t.Fatalf("after recovering: %v", e)
	}
	var hostIDs []string
	var payload []byte
	if err := f.s.Pool.QueryRow(ctx, `SELECT host_ids::text[], payload FROM alert_events WHERE subject = $1 ORDER BY id LIMIT 1`,
		"agent:"+agentID).Scan(&hostIDs, &payload); err != nil {
		t.Fatal(err)
	}
	var ev notify.Event
	_ = json.Unmarshal(payload, &ev)
	if len(hostIDs) != 1 || hostIDs[0] != f.hostID || ev.Agent == nil || ev.Agent.ID != agentID || len(ev.Agent.Hosts) != 1 {
		t.Fatalf("agent event: hosts %v payload %s", hostIDs, payload)
	}
	// Revoked agents are forgotten and never alert.
	f.exec(`UPDATE agents SET revoked_at = now(), last_seen_at = $2 WHERE id = $1`, agentID, now.Add(-time.Hour))
	check(now.Add(10 * time.Minute))
	if e := events(); len(e) != 2 {
		t.Fatalf("revoked agent emitted: %v", e)
	}
	// No rule for the type -> no event written.
	f.exec(`UPDATE alert_rules SET event_types = '{finding.opened}' WHERE user_id = $1`, f.userID)
	f.exec(`UPDATE agents SET revoked_at = NULL, last_seen_at = $2 WHERE id = $1`, agentID, now.Add(10*time.Minute))
	check(now.Add(10 * time.Minute)) // silent re-observation (online)
	check(now.Add(20 * time.Minute)) // stale, but nobody listens
	if e := events(); len(e) != 2 {
		t.Fatalf("event written without a rule: %v", e)
	}
}

// Archived hosts (migration 0011) never alert: their finding transitions
// write no events, and agent events leave them out of host_ids and the
// payload, so a rule scoped to an archived host doesn't match.
func TestArchivedHostsDontAlert(t *testing.T) {
	f := newAlertFixture(t)
	ctx := context.Background()
	archived, err := f.s.CreateHost(ctx, f.userID, "archived-"+f.tag)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE hosts SET archived_at = now() WHERE id = $1`, archived)
	ch := f.channel("fake", "fake", map[string]string{"room": "r"}, nil)
	f.rule("everything", ruleOpts{types: []string{notify.EventFindingResolved, notify.EventAgentStale}}, ch)

	// An open finding on each host, and no inventory: reconcile resolves
	// both, but only the active host's transition is written.
	for _, h := range []string{f.hostID, archived} {
		f.exec(`INSERT INTO findings (host_id, kind, dedup_key, vuln_key, source_package, status)
		        VALUES ($1, $2, 'pkg:swlib:CVE-1902-1', 'CVE-1902-1', 'swlib', 'open')`, h, findings.KindVulnerablePackage)
	}
	for h, want := range map[string]int{f.hostID: 1, archived: 0} {
		res, err := f.s.ReconcileHostFindings(ctx, h)
		if err != nil {
			t.Fatal(err)
		}
		if res.Resolved != 1 || res.AlertEvents != want {
			t.Fatalf("host %s: resolved %d, alert events %d, want 1, %d", h, res.Resolved, res.AlertEvents, want)
		}
		if n := f.count(`SELECT count(*) FROM alert_events WHERE $1::uuid = ANY (host_ids) AND type = $2`,
			h, notify.EventFindingResolved); n != want {
			t.Fatalf("host %s: %d finding events, want %d", h, n, want)
		}
	}

	// An agent collecting both hosts goes stale.
	now := time.Now().UTC().Truncate(time.Second)
	var agentID string
	if err := f.s.Pool.QueryRow(ctx, `
		INSERT INTO agents (user_id, name, push_interval_seconds, last_seen_at) VALUES ($1, $2, 60, $3) RETURNING id
	`, f.userID, "agent-"+f.tag, now).Scan(&agentID); err != nil {
		t.Fatal(err)
	}
	f.exec(`INSERT INTO agent_hosts (agent_id, host_id, mode, target_ref, address, port, username) VALUES ($1, $2, 'local', 'local', NULL, NULL, NULL), ($1, $3, 'ssh', 'ssh:old', '10.0.0.9', 22, 'upkeep')`,
		agentID, f.hostID, archived)
	for _, at := range []time.Time{now, now.Add(4 * time.Minute)} { // first observation, then stale
		if _, err := f.s.CheckAgentHealth(ctx, at); err != nil {
			t.Fatal(err)
		}
	}
	var hostIDs []string
	var payload []byte
	if err := f.s.Pool.QueryRow(ctx, `SELECT host_ids::text[], payload FROM alert_events WHERE subject = $1`,
		"agent:"+agentID).Scan(&hostIDs, &payload); err != nil {
		t.Fatal(err)
	}
	var ev notify.Event
	_ = json.Unmarshal(payload, &ev)
	if len(hostIDs) != 1 || hostIDs[0] != f.hostID || ev.Agent == nil || len(ev.Agent.Hosts) != 1 || ev.Agent.Hosts[0].ID != f.hostID {
		t.Fatalf("agent event: hosts %v payload %s", hostIDs, payload)
	}
}

// ---- alert_deliver: statuses, retries, the dashboard's test send ----

func TestDeliverWorker(t *testing.T) {
	f := newAlertFixture(t)
	ctx := context.Background()
	fake := &fakeNotifier{}
	w := &AlertDeliverWorker{Store: f.s, Cfg: AlertingConfig{Notifiers: notify.NewRegistry(fake)}}
	ch := f.channel("fake", "fake", map[string]string{"room": "r"}, map[string]string{"token": "x"})

	// A "send test" exactly as the dashboard inserts it (no payload).
	newDelivery := func(channelID string) string {
		var nid, did string
		if err := f.s.Pool.QueryRow(ctx, `INSERT INTO notifications (user_id, kind) VALUES ($1, 'test') RETURNING id`, f.userID).Scan(&nid); err != nil {
			t.Fatal(err)
		}
		if err := f.s.Pool.QueryRow(ctx, `
			INSERT INTO notification_deliveries (user_id, notification_id, channel_id, channel_name, channel_type)
			SELECT $1, $2, id, name, type FROM notification_channels WHERE id = $3 RETURNING id
		`, f.userID, nid, channelID).Scan(&did); err != nil {
			t.Fatal(err)
		}
		return did
	}
	job := func(id string, attempt, max int) *river.Job[AlertDeliverArgs] {
		return &river.Job[AlertDeliverArgs]{JobRow: &rivertype.JobRow{Attempt: attempt, MaxAttempts: max}, Args: AlertDeliverArgs{DeliveryID: id}}
	}
	status := func(id string) (s string, attempts int) {
		_ = f.s.Pool.QueryRow(ctx, `SELECT status, attempts FROM notification_deliveries WHERE id = $1`, id).Scan(&s, &attempts)
		return
	}

	ok := newDelivery(ch)
	if err := w.Work(ctx, job(ok, 1, 1)); err != nil {
		t.Fatal(err)
	}
	if s, a := status(ok); s != store.DeliveryDelivered || a != 1 {
		t.Fatalf("test send: %s after %d", s, a)
	}
	if got := fake.all(); len(got) != 1 || got[0].Kind != notify.KindTest || got[0].DeliveryID != ok || got[0].Events == nil {
		t.Fatalf("test notification: %+v", got)
	}
	// Duplicate job for a final delivery: no second send.
	_ = w.Work(ctx, job(ok, 1, 1))
	if len(fake.all()) != 1 {
		t.Fatal("final delivery re-sent")
	}

	// Retryable failure: error returned (River retries), status retrying;
	// on the last attempt it becomes failed.
	fake.err = errors.New("HTTP 503")
	retry := newDelivery(ch)
	if err := w.Work(ctx, job(retry, 1, 3)); err == nil {
		t.Fatal("retryable failure not returned")
	}
	if s, a := status(retry); s != store.DeliveryRetrying || a != 1 {
		t.Fatalf("after retryable failure: %s/%d", s, a)
	}
	if err := w.Work(ctx, job(retry, 3, 3)); err != nil {
		t.Fatalf("last attempt returned %v", err)
	}
	if s, a := status(retry); s != store.DeliveryFailed || a != 2 {
		t.Fatalf("after last attempt: %s/%d", s, a)
	}
	// Permanent failure: failed at once.
	fake.err = notify.Permanent(errors.New("HTTP 404"))
	perm := newDelivery(ch)
	if err := w.Work(ctx, job(perm, 1, 8)); err != nil {
		t.Fatal(err)
	}
	if s, _ := status(perm); s != store.DeliveryFailed {
		t.Fatalf("permanent: %s", s)
	}
	fake.err = nil
	// Disabled channels still take test sends but not alerts.
	f.exec(`UPDATE notification_channels SET enabled = false WHERE id = $1`, ch)
	tst := newDelivery(ch)
	_ = w.Work(ctx, job(tst, 1, 1))
	if s, _ := status(tst); s != store.DeliveryDelivered {
		t.Fatalf("test send on disabled channel: %s", s)
	}
	alert := newDelivery(ch)
	f.exec(`UPDATE notifications SET kind = 'alert' WHERE id = (SELECT notification_id FROM notification_deliveries WHERE id = $1)`, alert)
	_ = w.Work(ctx, job(alert, 1, 8))
	var lastErr string
	_ = f.s.Pool.QueryRow(ctx, `SELECT status || ':' || last_error FROM notification_deliveries WHERE id = $1`, alert).Scan(&lastErr)
	if lastErr != "failed:channel is disabled" {
		t.Fatalf("alert on disabled channel: %s", lastErr)
	}
	// Unknown type (e.g. a type removed from the build): failed, not retried.
	unknown := f.channel("gone", "carrier-pigeon", nil, nil)
	u := newDelivery(unknown)
	if err := w.Work(ctx, job(u, 1, 8)); err != nil {
		t.Fatal(err)
	}
	if s, _ := status(u); s != store.DeliveryFailed {
		t.Fatalf("unknown type: %s", s)
	}
	if n := f.count(`SELECT count(*) FROM notification_delivery_attempts a JOIN notification_deliveries d ON d.id = a.delivery_id WHERE d.user_id = $1`, f.userID); n != 7 {
		t.Fatalf("attempt rows = %d, want 7", n)
	}
}

func TestDeliverBackoff(t *testing.T) {
	prev := time.Duration(0)
	for n := 1; n <= DeliverMaxAttempts+2; n++ {
		d := NextDeliverRetry(n)
		if d < prev {
			t.Fatalf("backoff shrinks at attempt %d", n)
		}
		prev = d
	}
	if NextDeliverRetry(1) != 30*time.Second || NextDeliverRetry(100) != 6*time.Hour {
		t.Fatal("backoff bounds")
	}
}
