package store

// Report inputs (store/reports.go) against a real database: skipped unless
// SW_TEST_DATABASE_URL is set. Built on the inventory fixture (its own user
// and host); the other hosts, agents, findings, Docker rows, schedule and
// reports go with the user, the interned versions with the fixture's
// distro, and the image keys are deleted here.

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/reports"
)

func TestReportInputs(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	db := f.s.Pool
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	var userID string
	if err := db.QueryRow(ctx, `SELECT user_id FROM hosts WHERE id = $1`, f.hostID).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	img1, img2 := "sha256:"+f.distro+"-app", "sha256:"+f.distro+"-private"
	t.Cleanup(func() {
		// Before the fixture's cleanup: host_images reference the keys.
		_, _ = db.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
		_, _ = db.Exec(context.Background(), `DELETE FROM container_images WHERE image_id = ANY($1)`, []string{img1, img2})
	})

	now := time.Now().UTC().Truncate(time.Second)
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	day := 24 * time.Hour
	period := reports.Period{Start: ago(7 * day), End: now}

	// Hosts: web (the fixture's, labelled), db, and an archived one whose
	// data must not show anywhere.
	web := f.hostID
	exec(`UPDATE hosts SET label = 'web-1' WHERE id = $1`, web)
	dbHost, err := f.s.CreateHost(ctx, userID, "db-1")
	if err != nil {
		t.Fatal(err)
	}
	archived, err := f.s.CreateHost(ctx, userID, "old-1")
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE hosts SET archived_at = now() WHERE id = $1`, archived)

	// Agents: web's is fresh, db's has been silent for an hour (stale at a
	// 60s interval), the archived host's is stale but covers nothing.
	agent := func(name string, lastSeen time.Time, hosts ...string) string {
		var id string
		if err := db.QueryRow(ctx, `INSERT INTO agents (user_id, name, push_interval_seconds, last_seen_at)
			VALUES ($1, $2, 60, $3) RETURNING id`, userID, name, lastSeen).Scan(&id); err != nil {
			t.Fatal(err)
		}
		for _, h := range hosts {
			exec(`INSERT INTO agent_hosts (agent_id, host_id, mode) VALUES ($1, $2, 'local')`, id, h)
		}
		return id
	}
	agent("web-agent", now, web)
	staleID := agent("db-agent", ago(time.Hour), dbHost)
	agent("old-agent", ago(day), archived)

	// Snapshots: web needs a reboot since its second push and reports
	// Docker; db has no snapshot (no Docker collection).
	snapshot := func(host string, at time.Time, reboot bool, pkgs []string, status string) {
		exec(`INSERT INTO snapshots (host_id, schema_version, collected_at, received_at, os_id, os_version_id,
			reboot_required, reboot_packages, collector_status) VALUES ($1, 1, $2, $2, 'ubuntu', '22.04', $3, $4, $5)`,
			host, at, reboot, pkgs, status)
	}
	snapshot(web, ago(3*day), false, []string{}, `{}`)
	snapshot(web, ago(2*day), true, []string{"libc6"}, `{}`)
	snapshot(web, ago(time.Hour), true, []string{"linux-image-6.8", "libc6"}, `{"docker_images": {"status": "ok"}}`)
	snapshot(archived, ago(time.Hour), true, []string{"libc6"}, `{}`)

	// One interned binary version for the host findings' ecosystem/release.
	var svID int64
	if err := db.QueryRow(ctx, `INSERT INTO software_versions (ecosystem, distro, release, name, version, arch, source_name)
		VALUES ('deb', $1, 'jammy', 'libssl3', '1.0-1', 'amd64', 'openssl') RETURNING id`, f.distro).Scan(&svID); err != nil {
		t.Fatal(err)
	}

	type fnd struct {
		host, kind, key, vuln string
		fixed                 *string
		channel               *string
		sev                   string
		rank                  int
		kev                   bool
		status                string
		firstSeen             time.Time
		reopened, resolved    *time.Time
		image                 string
	}
	std := sp("standard")
	reopenedAt, resolvedAt := ago(day), ago(2*day)
	for _, x := range []fnd{
		// openssl on web and db: CVE-A needs 1.2-1, CVE-B (KEV) 1.10-1.
		{host: web, kind: "vulnerable_package", key: "pkg:openssl:CVE-A", vuln: "CVE-A", fixed: sp("1.2-1"), channel: std,
			sev: "high", rank: 5, status: "open", firstSeen: ago(30 * day), reopened: &reopenedAt},
		{host: web, kind: "vulnerable_package", key: "pkg:openssl:CVE-B", vuln: "CVE-B", fixed: sp("1.10-1"), channel: std,
			sev: "critical", rank: 6, kev: true, status: "open", firstSeen: ago(3 * day)},
		{host: dbHost, kind: "vulnerable_package", key: "pkg:openssl:CVE-A", vuln: "CVE-A", fixed: sp("1.2-1"), channel: std,
			sev: "high", rank: 5, status: "open", firstSeen: ago(40 * day)},
		// No fix yet.
		{host: dbHost, kind: "vulnerable_package", key: "pkg:zlib:CVE-C", vuln: "CVE-C", sev: "medium", rank: 4,
			status: "open", firstSeen: ago(40 * day)},
		// Resolved in the period, and one resolved before it.
		{host: web, kind: "vulnerable_package", key: "pkg:curl:CVE-D", vuln: "CVE-D", fixed: sp("8-1"), channel: std,
			sev: "low", rank: 2, status: "resolved", firstSeen: ago(20 * day), resolved: &resolvedAt},
		{host: web, kind: "vulnerable_package", key: "pkg:curl:CVE-E", vuln: "CVE-E", fixed: sp("8-1"), channel: std,
			sev: "low", rank: 2, status: "resolved", firstSeen: ago(20 * day), resolved: ptrTime(ago(10 * day))},
		// An image finding with a standard fix.
		{host: web, kind: "vulnerable_image", key: "img:app:zlib:CVE-F", vuln: "CVE-F", fixed: sp("1.3"), channel: std,
			sev: "medium", rank: 4, status: "open", firstSeen: ago(2 * day), image: img1},
		// The archived host's findings count nowhere.
		{host: archived, kind: "vulnerable_package", key: "pkg:openssl:CVE-A", vuln: "CVE-A", fixed: sp("9-1"), channel: std,
			sev: "critical", rank: 6, kev: true, status: "open", firstSeen: ago(day)},
	} {
		var imgID, imgOS, imgArch, imgVariant *string
		if x.image != "" {
			imgID, imgOS, imgArch, imgVariant = &x.image, sp("linux"), sp("amd64"), sp("")
		}
		exec(`INSERT INTO findings (host_id, kind, dedup_key, vuln_key, source_package, fixed_version, fix_channel,
				severity, severity_rank, is_kev, status, first_seen_at, reopened_at, resolved_at, software_ids, packages,
				image_id, image_os, image_arch, image_variant)
			VALUES ($1, $2, $3, $4, split_part($3, ':', 2), $5, $6, $7, $8, $9, $10, $11, $12, $13,
				CASE WHEN $2 = 'vulnerable_package' THEN ARRAY[$14::bigint] ELSE '{}' END, ARRAY['libssl3'],
				$15, $16, $17, $18)`,
			x.host, x.kind, x.key, x.vuln, x.fixed, x.channel, x.sev, x.rank, x.kev, x.status, x.firstSeen,
			x.reopened, x.resolved, svID, imgID, imgOS, imgArch, imgVariant)
	}

	// Docker: web runs two containers of img1 and one of img2 (no package
	// list); an image on the host no container uses isn't in the report.
	for _, id := range []string{img1, img2} {
		exec(`INSERT INTO container_images (image_id, os, arch, variant) VALUES ($1, 'linux', 'amd64', '')`, id)
		exec(`INSERT INTO host_images (host_id, image_id, repo_tags, repo_digests, os, arch, variant, row_key, row_hash,
				detail_hash, live_hash, first_seen_at)
			VALUES ($1, $2, $3, $4, 'linux', 'amd64', '', $2, 'h', 'd', 'l', $5)`,
			web, id, map[string][]string{img1: {"app:2", "app:latest"}, img2: {}}[id],
			[]string{"reg.example/private@sha256:1"}, ago(day))
	}
	for i, c := range []struct{ name, image string }{{"app-1", img1}, {"app-2", img1}, {"private", img2}} {
		exec(`INSERT INTO host_containers (host_id, container_id, name, image_id, state, row_key, row_hash,
				detail_hash, live_hash, first_seen_at)
			VALUES ($1, $2, $3, $4, 'running', $2, 'h', 'd', 'l', $5)`,
			web, f.distro+string(rune('a'+i)), c.name, c.image, ago(day))
	}

	tx, err := f.s.BeginReportRead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	in, err := f.s.LoadReportInputs(ctx, tx, userID, period)
	_ = tx.Rollback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sched := reports.ScheduleRef{ID: "s", Name: "Weekly", Cadence: reports.CadenceWeekly, Timezone: "UTC"}
	s := reports.Build(in, sched, reports.TriggerManual, period, now)

	webRef, dbRef := reports.HostRef{ID: web, Name: "web-1"}, reports.HostRef{ID: dbHost, Name: "db-1"}
	if s.Estate != (reports.Estate{Hosts: 2, Containers: 3, Images: 2}) {
		t.Errorf("estate = %+v", s.Estate)
	}
	if len(s.HostActions) != 1 {
		t.Fatalf("host actions = %+v", s.HostActions)
	}
	a := s.HostActions[0]
	if a.Package != "openssl" || a.FixedVersion != "1.10-1" || a.Tier != reports.TierPatchNow || !a.KEV ||
		a.WorstSeverity != "critical" || !slices.Equal(a.CVEs, []string{"CVE-A", "CVE-B"}) ||
		!slices.Equal(a.BinaryPackages, []string{"libssl3"}) ||
		!reflect.DeepEqual(a.Hosts, []reports.HostRef{dbRef, webRef}) || !a.OldestOpenAt.Equal(ago(40*day)) {
		t.Errorf("host action = %+v", a)
	}
	if len(s.ImageActions) != 1 {
		t.Fatalf("image actions = %+v", s.ImageActions)
	}
	ia := s.ImageActions[0]
	if ia.ImageID != img1 || ia.Tier != reports.TierWhenConvenient || ia.FixableFindings != 1 ||
		!slices.Equal(ia.ImageRefs, []string{"app:2", "app:latest"}) ||
		!slices.Equal(ia.Containers, []string{"app-1", "app-2"}) || !reflect.DeepEqual(ia.Hosts, []reports.HostRef{webRef}) {
		t.Errorf("image action = %+v", ia)
	}
	if s.NoFix.Findings != 1 || s.NoFix.HostPackageFindings != 1 || s.NoFix.WorstSeverity == nil || *s.NoFix.WorstSeverity != "medium" {
		t.Errorf("no fix = %+v", s.NoFix)
	}
	if len(s.RebootsRequired) != 1 || s.RebootsRequired[0].HostID != web ||
		!slices.Equal(s.RebootsRequired[0].Packages, []string{"libc6", "linux-image-6.8"}) ||
		s.RebootsRequired[0].Since == nil || !s.RebootsRequired[0].Since.Equal(ago(2*day)) {
		t.Errorf("reboots = %+v", s.RebootsRequired)
	}
	c := s.Coverage
	if len(c.StaleAgents) != 1 || c.StaleAgents[0].AgentID != staleID || c.StaleAgents[0].LastSeenAt == nil ||
		!c.StaleAgents[0].LastSeenAt.Equal(ago(time.Hour)) || !reflect.DeepEqual(c.StaleAgents[0].Hosts, []reports.HostRef{dbRef}) {
		t.Errorf("stale agents = %+v", c.StaleAgents)
	}
	if !reflect.DeepEqual(c.HostsWithoutDocker, []reports.HostRef{dbRef}) {
		t.Errorf("hosts without docker = %+v", c.HostsWithoutDocker)
	}
	wantNotScored := []reports.ImageNotScored{
		{ImageID: img1, ImageRefs: []string{"app:2", "app:latest"}, OS: "linux", Arch: "amd64", Status: "none"},
		{ImageID: img2, ImageRefs: []string{"reg.example/private@sha256:1"}, OS: "linux", Arch: "amd64", Status: "none"},
	}
	if !reflect.DeepEqual(c.ImagesNotScored, wantNotScored) {
		t.Errorf("images not scored = %+v", c.ImagesNotScored)
	}
	// Opened: CVE-B and CVE-F first seen, CVE-A on web reopened; resolved:
	// CVE-D (CVE-E was resolved before the period).
	want := reports.Headline{PatchNow: 1, WhenConvenient: 1, ImagesToUpdate: 1, RebootsRequired: 1, NoFixFindings: 1,
		TotalOpenFindings: 5, OpenedSinceLast: 3, ResolvedSinceLast: 1, StaleAgents: 1}
	if s.Headline != want {
		t.Errorf("headline = %+v, want %+v", s.Headline, want)
	}
	wantHosts := []reports.HostSummary{
		{ID: dbHost, Name: "db-1", PatchNow: 1, NoFixFindings: 1, TotalOpenFindings: 2},
		{ID: web, Name: "web-1", PatchNow: 1, WhenConvenient: 1, ImagesToUpdate: 1, RebootRequired: true, TotalOpenFindings: 3},
	}
	if !reflect.DeepEqual(s.Hosts, wantHosts) {
		t.Errorf("hosts = %+v", s.Hosts)
	}

	// The schedule's latest report is the one to compare with.
	var schedID string
	if err := db.QueryRow(ctx, `INSERT INTO report_schedules (user_id, name, cadence, weekday, hour, timezone)
		VALUES ($1, 'Weekly', 'weekly', 1, 7, 'UTC') RETURNING id`, userID).Scan(&schedID); err != nil {
		t.Fatal(err)
	}
	tx, err = f.s.BeginReportRead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := f.s.LatestReport(ctx, tx, schedID); err != nil || p != nil {
		t.Errorf("latest report of a new schedule = %+v, %v", p, err)
	}
	_ = tx.Rollback(ctx)
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var newest string
	for i, at := range []time.Time{ago(14 * day), ago(7 * day)} {
		if err := db.QueryRow(ctx, `INSERT INTO reports (schedule_id, user_id, generated_at, period_start, period_end,
				ranking_version, snapshot, trigger)
			VALUES ($1, $2, $3, $3, $3, $4, $5, 'scheduled') RETURNING id`,
			schedID, userID, at, reports.RankingVersion, raw).Scan(&newest); err != nil {
			t.Fatal(i, err)
		}
	}
	tx, err = f.s.BeginReportRead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	p, err := f.s.LatestReport(ctx, tx, schedID)
	if err != nil || p == nil {
		t.Fatalf("latest report = %+v, %v", p, err)
	}
	if p.ID != newest || !p.GeneratedAt.Equal(ago(7*day)) || !reflect.DeepEqual(p.Snapshot.Hosts, s.Hosts) {
		t.Errorf("latest report = %s %v", p.ID, p.GeneratedAt)
	}
	if ch := reports.Compare(&p.Snapshot, p.ID, s); ch == nil || !ch.Comparable || ch.Metrics["patch_now"].Delta != 0 ||
		len(ch.HostsAdded) != 0 || len(ch.HostsArchived) != 0 {
		t.Errorf("changes = %+v", ch)
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
