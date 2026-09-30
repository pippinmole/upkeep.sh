package jobs

// Alerting integration tests against a real, fully migrated Postgres;
// skipped unless SW_TEST_DATABASE_URL is set. Every test in this file
// drains the global alert_events outbox, so they are sequential (no
// t.Parallel) and live in one package; other packages' tests write no
// alert events (their workspaces' only rule is the seeded default, which has
// no channels).
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/pippinmole/upkeep.sh/server/internal/alerting"
	"github.com/pippinmole/upkeep.sh/server/internal/feeds"
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
	t           *testing.T
	s           *store.Store
	tag         string
	workspaceID string
	hostID      string
	cves        []string
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
	if err := s.Pool.QueryRow(ctx, `INSERT INTO workspaces (name) VALUES ($1) RETURNING id`,
		f.tag+"@test.invalid").Scan(&f.workspaceID); err != nil {
		t.Fatal(err)
	}
	if f.hostID, err = s.CreateHost(ctx, f.workspaceID, "web-"+f.tag); err != nil {
		t.Fatal(err)
	}
	// Migration 0024 seeds the SSH default for every new workspace; tests set
	// up their own rules.
	var seeded int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM alert_rules WHERE workspace_id = $1 AND default_key = 'ssh_port_22'`,
		f.workspaceID).Scan(&seeded); err != nil || seeded != 1 {
		t.Fatalf("default rule not seeded: %d %v", seeded, err)
	}
	if _, err := s.Pool.Exec(ctx, `DELETE FROM alert_rules WHERE workspace_id = $1`, f.workspaceID); err != nil {
		t.Fatal(err)
	}
	// Anything still pending in the outbox belongs to an earlier, aborted
	// run: mark it processed so it can't leak into this test's counts.
	_, _ = s.Pool.Exec(ctx, `UPDATE alert_events SET processed_at = now() WHERE processed_at IS NULL`)
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = s.Pool.Exec(ctx, `DELETE FROM workspaces WHERE id = $1`, f.workspaceID)
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
		INSERT INTO notification_channels (workspace_id, name, type, config, secrets) VALUES ($1, $2, $3, $4, $5) RETURNING id
	`, f.workspaceID, name, typ, c, s).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	return id
}

type ruleOpts struct {
	hostIDs   []string
	noResolve bool          // notify_on_resolve off
	digest    time.Duration // > 0: digest mode
	createdAt time.Time
}

// rule inserts an alert rule the way the dashboard does (condition JSON,
// host scope, channels).
func (f *alertFixture) rule(name, condition string, o ruleOpts, channels ...string) string {
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
		INSERT INTO alert_rules (workspace_id, name, condition, host_ids, notify_on_resolve, digest, digest_interval_seconds, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id
	`, f.workspaceID, name, condition, o.hostIDs, !o.noResolve, o.digest > 0, interval, o.createdAt).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	for _, c := range channels {
		f.exec(`INSERT INTO alert_rule_channels (rule_id, channel_id, workspace_id) VALUES ($1, $2, $3)`, id, c, f.workspaceID)
	}
	return id
}

func (f *alertFixture) count(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.s.Pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (f *alertFixture) host(name string) string {
	f.t.Helper()
	id, err := f.s.CreateHost(context.Background(), f.workspaceID, name+"-"+f.tag)
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

// listen opens a host_listeners range (as ingest would).
func (f *alertFixture) listen(host, transport, addr string, port int, proc string) {
	f.t.Helper()
	proto := transport
	if strings.Contains(addr, ":") {
		proto += "6"
	}
	f.exec(`INSERT INTO host_listeners (host_id, transport, proto, local_addr, port, process_name, row_key, row_hash, first_seen_at)
	        VALUES ($1, $2, $3, $4, $5::int, NULLIF($6, ''), $3 || ' ' || $4 || ':' || $5::int, 'h', now() - interval '1 hour')`,
		host, transport, proto, addr, port, proc)
}

// unlisten closes a host's open listener ranges on a port.
func (f *alertFixture) unlisten(host string, port int) {
	f.t.Helper()
	f.exec(`UPDATE host_listeners SET removed_at = now() WHERE host_id = $1 AND port = $2 AND removed_at IS NULL`, host, port)
}

func (f *alertFixture) evaluate(hostID string) store.RuleEvalResult {
	f.t.Helper()
	res, err := f.s.EvaluateAlertRules(context.Background(), time.Now().UTC(), hostID, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return res
}

type inst struct {
	Host, Subject, State, Reason, Title string
	Details                             map[string]any
}

// instances lists a rule's alert instances, oldest first.
func (f *alertFixture) instances(ruleID string) []inst {
	f.t.Helper()
	rows, err := f.s.Pool.Query(context.Background(), `
		SELECT host_id::text, subject, state, COALESCE(resolved_reason, ''), title, details
		FROM alert_instances WHERE rule_id = $1 ORDER BY fired_at, host_id, subject`, ruleID)
	if err != nil {
		f.t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (inst, error) {
		var i inst
		err := r.Scan(&i.Host, &i.Subject, &i.State, &i.Reason, &i.Title, &i.Details)
		return i, err
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

func (f *alertFixture) firing(ruleID string) []inst {
	var out []inst
	for _, i := range f.instances(ruleID) {
		if i.State == "firing" {
			out = append(out, i)
		}
	}
	return out
}

func (f *alertFixture) events(ruleID, typ string) int {
	return f.count(`SELECT count(*) FROM alert_events WHERE rule_id = $1 AND type = $2`, ruleID, typ)
}

const sshRule = `{"property":"listening_port","operator":"in","value":[22],"options":{"bind":"non_loopback","protocol":"tcp"}}`

// ---- Default rules ----

// Every new workspace gets the SSH default (migration 0024's trigger), and
// every catalogue property has an evaluator.
func TestDefaultRuleSeeded(t *testing.T) {
	f := newAlertFixture(t) // asserts the seeded rule, then removes it
	f.exec(`INSERT INTO workspaces (name) VALUES ($1)`, "seed-"+f.tag+"@test.invalid")
	var cond []byte
	var name string
	var channels int
	if err := f.s.Pool.QueryRow(context.Background(), `
		SELECT r.name, r.condition, (SELECT count(*) FROM alert_rule_channels c WHERE c.rule_id = r.id)
		FROM alert_rules r JOIN workspaces w ON w.id = r.workspace_id
		WHERE w.name = $1 AND r.default_key = 'ssh_port_22' AND r.enabled AND r.host_ids IS NULL`,
		"seed-"+f.tag+"@test.invalid").Scan(&name, &cond, &channels); err != nil {
		t.Fatal(err)
	}
	f.exec(`DELETE FROM workspaces WHERE name = $1`, "seed-"+f.tag+"@test.invalid")
	c, err := alerting.ParseCondition(cond)
	if err != nil || c.Property != alerting.PropListeningPort || c.Ints()[0] != 22 || channels != 0 {
		t.Fatalf("seeded rule %q %s: %v", name, cond, err)
	}
	// Seeding again is a no-op.
	f.exec(`SELECT seed_default_alert_rules($1)`, f.workspaceID)
	f.exec(`SELECT seed_default_alert_rules($1)`, f.workspaceID)
	if n := f.count(`SELECT count(*) FROM alert_rules WHERE workspace_id = $1`, f.workspaceID); n != 1 {
		t.Fatalf("%d rules after seeding twice", n)
	}
}

// ---- listening_port, state machine and dedup ----

func TestListeningPortRule(t *testing.T) {
	f := newAlertFixture(t)
	ctx := context.Background()
	h := f.hostID
	f.listen(h, "tcp", "0.0.0.0", 22, "sshd")
	f.listen(h, "tcp", "::", 22, "sshd")
	f.listen(h, "tcp", "127.0.0.1", 5432, "postgres")
	f.listen(h, "udp", "0.0.0.0", 53, "")
	ch := f.channel("fake", "fake", map[string]string{"room": "r"}, nil)
	ssh := f.rule("ssh", sshRule, ruleOpts{}, ch)
	allow := f.rule("allowlist", `{"property":"listening_port","operator":"not_in","value":[22],"options":{"protocol":"any"}}`, ruleOpts{})
	loop := f.rule("loopback db", `{"property":"listening_port","operator":"in","value":[5432],"options":{"bind":"loopback"}}`, ruleOpts{})
	wild := f.rule("wildcard db", `{"property":"listening_port","operator":"in","value":[5432],"options":{"bind":"all_interfaces"}}`, ruleOpts{})

	res := f.evaluate(h)
	if res.Fired != 3 || res.Events != 1 {
		t.Fatalf("first pass: %+v", res)
	}
	got := f.firing(ssh)
	if len(got) != 1 || got[0].Subject != "tcp/22" || got[0].Title != "Port 22/tcp is listening" ||
		fmt.Sprint(got[0].Details["addresses"]) != "[0.0.0.0 ::]" || fmt.Sprint(got[0].Details["processes"]) != "[sshd]" {
		t.Fatalf("ssh: %+v", got)
	}
	if got := f.firing(allow); len(got) != 1 || got[0].Subject != "udp/53" || got[0].Title != "Port 53/udp is listening (not allowed)" {
		t.Fatalf("allowlist (loopback 5432 isn't counted): %+v", got)
	}
	if len(f.firing(loop)) != 1 || len(f.firing(wild)) != 0 {
		t.Fatal("bind options")
	}
	if f.events(allow, notify.EventAlertFiring) != 0 {
		t.Fatal("a rule without channels wrote events")
	}

	// Every later snapshot: nothing new (the state machine is the dedup).
	for range 3 {
		if res := f.evaluate(h); res.Fired+res.Resolved+res.Events+res.Refreshed != 0 {
			t.Fatalf("repeat pass: %+v", res)
		}
	}

	var enqueued []string
	opt := store.AlertOptions{DashboardURL: "https://upkeep.example", Enqueue: func(_ context.Context, _ pgx.Tx, ids []string) error {
		enqueued = append(enqueued, ids...)
		return nil
	}}
	r, err := f.s.EvaluateAlerts(ctx, time.Now(), opt)
	if err != nil || r.Events != 1 || r.Sent != 1 || r.Notifications != 1 || len(enqueued) != 1 {
		t.Fatalf("dispatch: %+v %v", r, err)
	}
	var payload []byte
	if err := f.s.Pool.QueryRow(ctx, `SELECT payload FROM notifications WHERE rule_id = $1`, ssh).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var n notify.Notification
	_ = json.Unmarshal(payload, &n)
	if len(n.Events) != 1 || n.Version != notify.PayloadVersion || n.Summary != "Port 22/tcp is listening on web-"+f.tag {
		t.Fatalf("notification: %s", payload)
	}
	ev := n.Events[0]
	if ev.Type != notify.EventAlertFiring || ev.Alert == nil || ev.Alert.Property != "listening_port" || ev.Alert.Subject != "tcp/22" ||
		ev.Alert.State != "firing" || ev.Host == nil || ev.Host.ID != h || ev.URL != "https://upkeep.example/dashboard/alerts?host="+h {
		t.Fatalf("event: %s", payload)
	}

	// A new address on the same port refreshes the alert, no event.
	f.listen(h, "tcp", "10.0.0.5", 22, "sshd")
	if res := f.evaluate(h); res.Refreshed != 1 || res.Events != 0 {
		t.Fatalf("refresh: %+v", res)
	}
	// sshd stops: resolved (cleared), with a resolved event.
	f.unlisten(h, 22)
	if res := f.evaluate(h); res.Resolved != 1 || res.Events != 1 {
		t.Fatalf("resolve: %+v", res)
	}
	if all := f.instances(ssh); len(all) != 1 || all[0].State != "resolved" || all[0].Reason != "cleared" {
		t.Fatalf("after resolve: %+v", all)
	}
	r, _ = f.s.EvaluateAlerts(ctx, time.Now(), opt)
	if r.Sent != 1 || r.Notifications != 1 {
		t.Fatalf("resolved dispatch: %+v", r)
	}
	// Listening again: a new episode (history keeps the old one).
	f.listen(h, "tcp", "0.0.0.0", 22, "sshd")
	f.evaluate(h)
	if all := f.instances(ssh); len(all) != 2 || all[1].State != "firing" {
		t.Fatalf("refire: %+v", all)
	}
	// Without notify_on_resolve, a resolution writes no event.
	f.exec(`UPDATE alert_rules SET notify_on_resolve = false WHERE id = $1`, ssh)
	f.unlisten(h, 22)
	if res := f.evaluate(h); res.Resolved != 1 || res.Events != 0 {
		t.Fatalf("resolve without notify: %+v", res)
	}
	if f.events(ssh, notify.EventAlertResolved) != 1 || f.events(ssh, notify.EventAlertFiring) != 2 {
		t.Fatal("event counts")
	}
}

// Bookkeeping resolutions (rule edited, disabled, deleted; host out of
// scope or archived) are silent.
func TestSilentResolutions(t *testing.T) {
	f := newAlertFixture(t)
	h1, h2, h3 := f.hostID, f.host("h2"), f.host("h3")
	for _, h := range []string{h1, h2, h3} {
		f.listen(h, "tcp", "0.0.0.0", 22, "sshd")
	}
	ch := f.channel("fake", "fake", map[string]string{"room": "r"}, nil)
	rule := f.rule("ssh", sshRule, ruleOpts{}, ch)
	if res := f.evaluate(""); len(f.firing(rule)) != 3 || f.events(rule, notify.EventAlertFiring) != 3 {
		t.Fatalf("all hosts: %+v", res)
	}
	reason := func(host string) string {
		t.Helper()
		var r string
		for _, i := range f.instances(rule) {
			if i.Host == host {
				r = i.State + ":" + i.Reason
			}
		}
		return r
	}

	f.exec(`UPDATE hosts SET archived_at = now() WHERE id = $1`, h3)
	f.evaluate(h3)
	if got := reason(h3); got != "resolved:host_archived" {
		t.Fatalf("archived: %s", got)
	}
	f.exec(`UPDATE alert_rules SET host_ids = ARRAY[$2::uuid] WHERE id = $1`, rule, h1)
	f.evaluate("")
	if got := reason(h2); got != "resolved:out_of_scope" {
		t.Fatalf("scope: %s", got)
	}
	f.exec(`UPDATE alert_rules SET condition = jsonb_set(condition, '{value}', '[2222]') WHERE id = $1`, rule)
	f.evaluate(h1)
	if got := reason(h1); got != "resolved:rule_changed" {
		t.Fatalf("edited: %s", got)
	}
	f.exec(`UPDATE alert_rules SET condition = $2 WHERE id = $1`, rule, sshRule)
	f.evaluate(h1)
	f.exec(`UPDATE alert_rules SET enabled = false WHERE id = $1`, rule)
	f.evaluate(h1)
	if got := reason(h1); got != "resolved:rule_disabled" {
		t.Fatalf("disabled: %s", got)
	}
	f.exec(`UPDATE alert_rules SET enabled = true WHERE id = $1`, rule)
	f.evaluate(h1)
	f.exec(`DELETE FROM alert_rules WHERE id = $1`, rule)
	f.evaluate(h1)
	var state, reasonCol, name string
	if err := f.s.Pool.QueryRow(context.Background(), `
		SELECT state, resolved_reason, rule_name FROM alert_instances
		WHERE host_id = $1 AND rule_id IS NULL ORDER BY fired_at DESC LIMIT 1`, h1).Scan(&state, &reasonCol, &name); err != nil {
		t.Fatal(err)
	}
	if state != "resolved" || reasonCol != "rule_deleted" || name != "ssh" {
		t.Fatalf("deleted rule: %s %s %s", state, reasonCol, name)
	}
	// Only the three first firings and two re-firings were ever news.
	if n := f.count(`SELECT count(*) FROM alert_events e JOIN alert_instances i ON i.id = e.instance_id
	                 WHERE i.workspace_id = $1 AND e.type = 'alert.resolved'`, f.workspaceID); n != 0 {
		t.Fatalf("%d resolved events for silent resolutions", n)
	}
	if n := f.count(`SELECT count(*) FROM alert_instances WHERE workspace_id = $1`, f.workspaceID); n != 5 {
		t.Fatalf("history rows: %d", n)
	}
}

// ---- The other properties' evaluators ----

func TestPropertyEvaluators(t *testing.T) {
	f := newAlertFixture(t)
	h, h2 := f.hostID, f.host("db")
	rule := func(cond string) string { return f.rule(cond[:min(len(cond), 100)], cond, ruleOpts{}) }
	subjects := func(rule string) string {
		var s []string
		for _, i := range f.firing(rule) {
			host := "h"
			if i.Host == h2 {
				host = "h2"
			}
			s = append(s, host+":"+i.Subject)
		}
		return strings.Join(s, ",")
	}

	// Packages: h has an inventory with Telnetd; h2 has none (unknown).
	var sw int64
	if err := f.s.Pool.QueryRow(context.Background(), `
		INSERT INTO software_versions (ecosystem, distro, release, name, version) VALUES ('deb', $1, 'jammy', 'Telnetd', '0.17-44')
		RETURNING id`, f.tag).Scan(&sw); err != nil {
		t.Fatal(err)
	}
	f.exec(`INSERT INTO host_software (host_id, software_id, first_seen_at) VALUES ($1, $2, now())`, h, sw)
	f.exec(`INSERT INTO host_inventory_state (host_id, ecosystem, confirmed_at, changed_at) VALUES ($1, 'deb', now(), now())`, h)
	installed := rule(`{"property":"package_installed","operator":"installed","value":["telnetd","nano"]}`)
	missing := rule(`{"property":"package_installed","operator":"not_installed","value":["telnetd","fail2ban"]}`)

	// OS: h is Ubuntu, h2 unknown.
	f.exec(`UPDATE hosts SET os_family = 'linux', os_id = 'ubuntu', os_version = '22.04' WHERE id = $1`, h)
	isUbuntu := rule(`{"property":"os","operator":"in","value":["ubuntu"]}`)
	notDebian := rule(`{"property":"os","operator":"not_in","value":["debian","windows"]}`)
	isLinux := rule(`{"property":"os","operator":"in","value":["linux"]}`)

	// Snapshots: h needs a reboot and its dpkg collector failed; h2's
	// reboot collector failed (unknown).
	f.exec(`INSERT INTO snapshots (host_id, schema_version, collected_at, os_id, os_version_id, reboot_required, reboot_packages, collector_status)
	        VALUES ($1, 1, now(), 'ubuntu', '22.04', true, '{linux-image-6.8.0-45-generic}',
	                '{"reboot_required":{"status":"ok"},"deb_packages":{"status":"error","error":"dpkg status missing"},"os":{"status":"ok"}}'),
	               ($2, 1, now(), 'ubuntu', '22.04', false, '{}', '{"reboot_required":{"status":"error","error":"x"}}')`, h, h2)
	reboot := rule(`{"property":"reboot_required","operator":"is_true"}`)
	anyCollector := rule(`{"property":"collector_failed","operator":"any"}`)
	tcpCollector := rule(`{"property":"collector_failed","operator":"in","value":["tcp_listeners"]}`)

	// Last seen: h two hours ago, h2 just now.
	f.exec(`UPDATE hosts SET last_seen_at = now() - interval '2 hours' WHERE id = $1`, h)
	f.exec(`UPDATE hosts SET last_seen_at = now() WHERE id = $1`, h2)
	notSeen := rule(`{"property":"host_not_seen","operator":"for_more_than","value":30}`)

	// Findings on h: an open high, an open low KEV, a resolved critical.
	f.exec(`INSERT INTO findings (host_id, kind, dedup_key, vuln_key, source_package, status, severity, severity_rank, is_kev)
	        VALUES ($1, 'vulnerable_package', 'pkg:swlib:CVE-1', 'CVE-1', 'swlib', 'open', 'high', 5, false),
	               ($1, 'vulnerable_package', 'pkg:swlib:CVE-2', 'CVE-2', 'swlib', 'open', 'low', 2, true),
	               ($1, 'vulnerable_package', 'pkg:swlib:CVE-3', 'CVE-3', 'swlib', 'resolved', 'critical', 6, false)`, h)
	high := rule(`{"property":"vulnerability","operator":"severity_at_least","value":"high"}`)
	kev := rule(`{"property":"vulnerability","operator":"kev"}`)
	images := rule(`{"property":"vulnerability","operator":"severity_at_least","value":"low","options":{"source":"images"}}`)

	f.evaluate(h)
	f.evaluate(h2)
	for name, c := range map[string]struct{ rule, want string }{
		"installed":      {installed, "h:telnetd"},
		"not installed":  {missing, "h:fail2ban"},
		"os in":          {isUbuntu, "h:"},
		"os not in":      {notDebian, "h:"},
		"os family":      {isLinux, "h:"},
		"reboot":         {reboot, "h:"},
		"any collector":  {anyCollector, "h:deb_packages,h2:reboot_required"},
		"tcp collector":  {tcpCollector, ""},
		"not seen":       {notSeen, "h:"},
		"severity floor": {high, "h:pkg:swlib:CVE-1"},
		"kev":            {kev, "h:pkg:swlib:CVE-2"},
		"images only":    {images, ""},
	} {
		if got := subjects(c.rule); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
	checkTitle := func(rule, want string) {
		t.Helper()
		if got := f.firing(rule); len(got) == 0 || got[0].Title != want {
			t.Errorf("title: %+v, want %q", got, want)
		}
	}
	checkTitle(installed, "Package telnetd is installed")
	checkTitle(missing, "Package fail2ban is not installed")
	checkTitle(isUbuntu, "OS is ubuntu 22.04")
	checkTitle(notDebian, "OS ubuntu 22.04 is not allowed")
	checkTitle(reboot, "Reboot required")
	checkTitle(notSeen, "Not seen for more than 30 minutes")
	checkTitle(high, "High CVE-1 in swlib")
	checkTitle(kev, "KEV CVE-2 in swlib")
	if d := f.firing(anyCollector)[0].Details; d["error"] != "dpkg status missing" {
		t.Errorf("collector details %v", d)
	}
	if d := f.firing(high)[0].Details; d["vuln_key"] != "CVE-1" || d["severity"] != "high" || d["kind"] != "vulnerable_package" {
		t.Errorf("finding details %v", d)
	}

	// Changes resolve: reported again, package removed, finding fixed,
	// newest snapshot without a reboot.
	f.exec(`UPDATE hosts SET last_seen_at = now() WHERE id = $1`, h)
	f.exec(`UPDATE host_software SET removed_at = now() + interval '1 second' WHERE host_id = $1`, h)
	f.exec(`UPDATE findings SET status = 'resolved' WHERE host_id = $1 AND vuln_key = 'CVE-1'`, h)
	f.exec(`INSERT INTO snapshots (host_id, schema_version, collected_at, os_id, os_version_id, reboot_required, collector_status, received_at)
	        VALUES ($1, 1, now(), 'ubuntu', '22.04', false, '{"reboot_required":{"status":"ok"}}', now() + interval '1 second')`, h)
	f.evaluate(h)
	for name, c := range map[string]struct{ rule, want string }{
		"installed":     {installed, ""},
		"not installed": {missing, "h:fail2ban,h:telnetd"},
		"reboot":        {reboot, ""},
		"any collector": {anyCollector, "h2:reboot_required"},
		"not seen":      {notSeen, ""},
		"severity":      {high, ""},
		"kev":           {kev, "h:pkg:swlib:CVE-2"},
	} {
		if got := subjects(c.rule); got != c.want {
			t.Errorf("after changes, %s: %q, want %q", name, got, c.want)
		}
	}
	// Unknown never resolves: h's reboot collector fails in its newest
	// snapshot while an alert fires.
	f.exec(`INSERT INTO snapshots (host_id, schema_version, collected_at, os_id, os_version_id, reboot_required, collector_status, received_at)
	        VALUES ($1, 1, now(), 'ubuntu', '22.04', true, '{"reboot_required":{"status":"ok"}}', now() + interval '2 seconds'),
	               ($1, 1, now(), 'ubuntu', '22.04', false, '{"reboot_required":{"status":"error"}}', now() + interval '3 seconds')`, h)
	f.evaluate(h) // sees only the newest: unknown, nothing fires
	if got := subjects(reboot); got != "" {
		t.Fatalf("unknown fired: %q", got)
	}
	f.exec(`DELETE FROM snapshots WHERE host_id = $1 AND received_at > now() + interval '2500 milliseconds'`, h)
	f.evaluate(h)
	f.exec(`INSERT INTO snapshots (host_id, schema_version, collected_at, os_id, os_version_id, reboot_required, collector_status, received_at)
	        VALUES ($1, 1, now(), 'ubuntu', '22.04', false, '{"reboot_required":{"status":"error"}}', now() + interval '4 seconds')`, h)
	f.evaluate(h)
	if got := subjects(reboot); got != "h:" {
		t.Fatalf("a failed collector resolved the alert: %q", got)
	}
}

// ---- Dispatch: digests, rules that stop sending ----

func TestDispatchDigestAndSkips(t *testing.T) {
	f := newAlertFixture(t)
	ctx := context.Background()
	h := f.hostID
	f.listen(h, "tcp", "0.0.0.0", 22, "sshd")
	ch := f.channel("fake", "fake", map[string]string{"room": "r"}, nil)
	t0 := time.Now().UTC().Truncate(time.Second)
	digest := f.rule("digest", sshRule, ruleOpts{digest: time.Hour, createdAt: t0.Add(-2 * time.Hour)}, ch)
	immediate := f.rule("immediate", sshRule, ruleOpts{}, ch)
	quiet := f.rule("no resolve", sshRule, ruleOpts{noResolve: true}, ch)

	opt := store.AlertOptions{}
	f.evaluate(h)
	r, err := f.s.EvaluateAlerts(ctx, t0, opt)
	if err != nil || r.Events != 3 || r.Digested != 1 || r.Notifications != 2 {
		t.Fatalf("firing: %+v %v", r, err)
	}
	// Resolved: the quiet rule wrote no event; the immediate rule is
	// disabled before dispatch, so its event is skipped.
	f.unlisten(h, 22)
	if res := f.evaluate(h); res.Resolved != 3 || res.Events != 2 {
		t.Fatalf("resolve: %+v", res)
	}
	f.exec(`UPDATE alert_rules SET enabled = false WHERE id = $1`, immediate)
	r, _ = f.s.EvaluateAlerts(ctx, t0, opt)
	if r.Events != 2 || r.Skipped != 1 || r.Digested != 1 || r.Notifications != 0 {
		t.Fatalf("resolved: %+v", r)
	}
	d, err := f.s.FlushDigests(ctx, t0.Add(time.Minute), opt)
	if err != nil || d.Rules != 1 || d.Events != 2 || d.Notifications != 1 {
		t.Fatalf("digest: %+v %v", d, err)
	}
	var payload []byte
	if err := f.s.Pool.QueryRow(ctx, `SELECT payload FROM notifications WHERE rule_id = $1 AND kind = 'digest'`, digest).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var n notify.Notification
	_ = json.Unmarshal(payload, &n)
	if len(n.Events) != 2 || n.Events[0].Type != notify.EventAlertFiring || n.Events[1].Type != notify.EventAlertResolved ||
		!strings.HasPrefix(n.Summary, "Digest: 1 firing, 1 resolved alerts") {
		t.Fatalf("digest notification: %s", payload)
	}
	if d, _ := f.s.FlushDigests(ctx, t0.Add(30*time.Minute), opt); d.Rules != 0 {
		t.Fatal("digest before its interval")
	}
	if f.events(quiet, notify.EventAlertResolved) != 0 {
		t.Fatal("quiet rule wrote a resolved event")
	}
}

// ---- End to end: findings reconcile -> rule -> signed webhook ----

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
	ruleID := f.rule("High and up", `{"property":"vulnerability","operator":"severity_at_least","value":"high"}`,
		ruleOpts{hostIDs: []string{f.hostID}}, hook, fakeCh)

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

	// 1. Vulnerable version installed -> finding opened -> the host's rules
	// are evaluated -> alert fires -> webhook.
	push(1, "1.0-1")
	if _, err := client.Insert(ctx, ReconcileHostArgs{HostID: f.hostID}, nil); err != nil {
		t.Fatal(err)
	}
	n := await(notify.EventAlertFiring)
	ev := n.Events[0]
	if n.Kind != notify.KindAlert || n.Rule == nil || n.Rule.ID != ruleID || n.Version != notify.PayloadVersion ||
		ev.Alert == nil || ev.Alert.Property != "vulnerability" || ev.Alert.State != "firing" ||
		ev.Finding == nil || ev.Finding.VulnKey != cve || ev.Finding.Severity != "high" || ev.Finding.Status != "open" ||
		ev.Host == nil || ev.Host.ID != f.hostID ||
		ev.URL != "https://upkeep.example/dashboard/hosts/"+f.hostID+"/vulnerabilities?v="+cve {
		t.Fatalf("firing notification: %+v / %+v", n, ev)
	}

	// 2. Upgrade to the fixed version -> finding resolved -> alert resolves.
	push(2, "1.0-2")
	if _, err := client.Insert(ctx, ReconcileHostArgs{HostID: f.hostID}, nil); err != nil {
		t.Fatal(err)
	}
	n = await(notify.EventAlertResolved)
	if a := n.Events[0].Alert; a == nil || a.State != "resolved" || a.ResolvedAt == nil || a.ID != ev.Alert.ID {
		t.Fatalf("resolved event: %+v", n.Events[0])
	}

	// The fake channel type got both, with its secret merged into config.
	deadline := time.Now().Add(10 * time.Second)
	for len(fake.all()) < 2 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	got := fake.all()
	if len(got) != 2 || got[0].Events[0].Type != notify.EventAlertFiring || fake.cfgs[0]["token"] != "t0k" || fake.cfgs[0]["room"] != "#sec" {
		t.Fatalf("fake notifier: %d notifications, cfg %v", len(got), fake.cfgs)
	}
	// Delivery log: 4 delivered deliveries, one attempt each.
	for time.Now().Before(deadline) && f.count(`SELECT count(*) FROM notification_deliveries WHERE workspace_id = $1 AND status = 'delivered'`, f.workspaceID) < 4 {
		time.Sleep(100 * time.Millisecond)
	}
	if n := f.count(`SELECT count(*) FROM notification_deliveries WHERE workspace_id = $1 AND status = 'delivered' AND attempts = 1 AND delivered_at IS NOT NULL`, f.workspaceID); n != 4 {
		t.Fatalf("delivered deliveries = %d, want 4", n)
	}
	if n := f.count(`SELECT count(*) FROM notification_delivery_attempts a JOIN notification_deliveries d ON d.id = a.delivery_id
	                 WHERE d.workspace_id = $1 AND d.channel_type = 'webhook' AND a.status_code = 204`, f.workspaceID); n != 2 {
		t.Fatalf("webhook attempts with 204 = %d, want 2", n)
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
		if err := f.s.Pool.QueryRow(ctx, `INSERT INTO notifications (workspace_id, kind) VALUES ($1, 'test') RETURNING id`, f.workspaceID).Scan(&nid); err != nil {
			t.Fatal(err)
		}
		if err := f.s.Pool.QueryRow(ctx, `
			INSERT INTO notification_deliveries (workspace_id, notification_id, channel_id, channel_name, channel_type)
			SELECT $1, $2, id, name, type FROM notification_channels WHERE id = $3 RETURNING id
		`, f.workspaceID, nid, channelID).Scan(&did); err != nil {
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
	if n := f.count(`SELECT count(*) FROM notification_delivery_attempts a JOIN notification_deliveries d ON d.id = a.delivery_id WHERE d.workspace_id = $1`, f.workspaceID); n != 7 {
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
