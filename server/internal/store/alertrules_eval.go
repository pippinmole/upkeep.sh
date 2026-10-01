package store

// Property evaluators for alert rules (docs/ALERTING.md "MVP property
// catalog"): one per internal/alerting catalog property, each a
// set-based query over the normalised host tables for a set of hosts.
// They report what currently matches and which hosts can't be read
// (unknown never resolves an alert).

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/alerting"
	"github.com/pippinmole/upkeep.sh/server/internal/findings"
)

// propertyEvaluator evaluates a validated condition over hostIDs (the
// rule's owner's active, in-scope hosts).
type propertyEvaluator func(ctx context.Context, tx pgx.Tx, c alerting.Condition, hostIDs []string, now time.Time) (alerting.Result, error)

var propertyEvaluators = map[string]propertyEvaluator{
	alerting.PropListeningPort:    evalListeningPort,
	alerting.PropPackageInstalled: evalPackageInstalled,
	alerting.PropOS:               evalOS,
	alerting.PropRebootRequired:   evalRebootRequired,
	alerting.PropVulnerability:    evalVulnerability,
	alerting.PropHostNotSeen:      evalHostNotSeen,
	alerting.PropCollectorFailed:  evalCollectorFailed,
}

// loopbackSQL mirrors the dashboard's listener classification
// (web/src/lib/queries-host-facts.ts): 127.0.0.0/8, ::1, v4-mapped 127/8.
const loopbackSQL = `(l.local_addr LIKE '127.%' OR l.local_addr = '::1' OR l.local_addr LIKE '::ffff:127.%')`

func details(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// listening_port: open host_listeners ranges. A failed listener collector
// keeps its ranges open (PROTOCOL.md), so the last known state holds.
func evalListeningPort(ctx context.Context, tx pgx.Tx, c alerting.Condition, hostIDs []string, _ time.Time) (alerting.Result, error) {
	allow := c.Operator == "not_in"
	rows, err := tx.Query(ctx, `
		SELECT l.host_id::text, l.transport, l.port,
		       array_agg(DISTINCT l.local_addr ORDER BY l.local_addr),
		       COALESCE(array_agg(DISTINCT l.process_name ORDER BY l.process_name)
		                FILTER (WHERE l.process_name IS NOT NULL AND l.process_name <> ''), '{}')
		FROM host_listeners l
		WHERE l.removed_at IS NULL AND l.host_id = ANY ($1::uuid[])
		  AND ($2 = 'any' OR l.transport = $2)
		  AND (l.port = ANY ($3::int[])) <> $4
		  AND CASE $5
		        WHEN 'any' THEN true
		        WHEN 'loopback' THEN `+loopbackSQL+`
		        WHEN 'all_interfaces' THEN l.local_addr IN ('0.0.0.0', '::', '*')
		        ELSE NOT `+loopbackSQL+`
		      END
		GROUP BY 1, 2, 3
		ORDER BY 1, 2, 3
	`, hostIDs, c.Options["protocol"], c.Ints(), allow, c.Options["bind"])
	if err != nil {
		return alerting.Result{}, fmt.Errorf("listening_port: %w", err)
	}
	var res alerting.Result
	res.Matches, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (alerting.Match, error) {
		var (
			host, transport string
			port            int
			addrs, procs    []string
		)
		if err := r.Scan(&host, &transport, &port, &addrs, &procs); err != nil {
			return alerting.Match{}, err
		}
		d := map[string]any{"transport": transport, "port": port, "addresses": addrs}
		if len(procs) > 0 {
			d["processes"] = procs
		}
		return alerting.Match{
			HostID: host, Subject: alerting.PortSubject(transport, port),
			Title: alerting.PortTitle(transport, port, allow), Details: details(d),
		}, nil
	})
	return res, err
}

// package_installed: the open host_software ranges, by name in any
// ecosystem, case-insensitively. not_installed needs a known inventory:
// hosts without any (no package collector ever succeeded) are unknown.
func evalPackageInstalled(ctx context.Context, tx pgx.Tx, c alerting.Condition, hostIDs []string, _ time.Time) (alerting.Result, error) {
	names := c.Strings()
	rows, err := tx.Query(ctx, `
		SELECT hs.host_id::text, lower(sv.name),
		       array_agg(DISTINCT sv.version ORDER BY sv.version),
		       array_agg(DISTINCT sv.ecosystem ORDER BY sv.ecosystem)
		FROM host_software hs JOIN software_versions sv ON sv.id = hs.software_id
		WHERE hs.removed_at IS NULL AND hs.host_id = ANY ($1::uuid[]) AND lower(sv.name) = ANY ($2::text[])
		GROUP BY 1, 2
		ORDER BY 1, 2
	`, hostIDs, names)
	if err != nil {
		return alerting.Result{}, fmt.Errorf("package_installed: %w", err)
	}
	type inst struct {
		host, name          string
		versions, ecosystem []string
	}
	installed, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (inst, error) {
		var i inst
		err := r.Scan(&i.host, &i.name, &i.versions, &i.ecosystem)
		return i, err
	})
	if err != nil {
		return alerting.Result{}, err
	}
	var res alerting.Result
	if c.Operator == "installed" {
		for _, i := range installed {
			res.Matches = append(res.Matches, alerting.Match{
				HostID: i.host, Subject: i.name, Title: alerting.PackageTitle(i.name, true),
				Details: details(map[string]any{"package": i.name, "versions": i.versions, "ecosystems": i.ecosystem}),
			})
		}
		return res, nil
	}
	rows, err = tx.Query(ctx, `
		SELECT DISTINCT host_id::text FROM host_inventory_state WHERE host_id = ANY ($1::uuid[])
	`, hostIDs)
	if err != nil {
		return res, err
	}
	known, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return res, err
	}
	have := map[[2]string]bool{}
	for _, i := range installed {
		have[[2]string{i.host, i.name}] = true
	}
	res.Unknown = map[string]bool{}
	for _, h := range hostIDs {
		if !slices.Contains(known, h) {
			res.Unknown[h] = true
			continue
		}
		for _, n := range names {
			if !have[[2]string{h, n}] {
				res.Matches = append(res.Matches, alerting.Match{
					HostID: h, Subject: n, Title: alerting.PackageTitle(n, false),
					Details: details(map[string]any{"package": n}),
				})
			}
		}
	}
	return res, nil
}

// os: hosts.os_id or hosts.os_family (ingest's current OS summary). A host
// whose OS is unknown is unknown.
func evalOS(ctx context.Context, tx pgx.Tx, c alerting.Condition, hostIDs []string, _ time.Time) (alerting.Result, error) {
	rows, err := tx.Query(ctx, `
		SELECT id::text, COALESCE(os_id, ''), COALESCE(os_version, ''), COALESCE(os_family, '')
		FROM hosts WHERE id = ANY ($1::uuid[]) ORDER BY id
	`, hostIDs)
	if err != nil {
		return alerting.Result{}, fmt.Errorf("os: %w", err)
	}
	defer rows.Close()
	res := alerting.Result{Unknown: map[string]bool{}}
	values := c.Strings()
	notIn := c.Operator == "not_in"
	for rows.Next() {
		var id, osID, version, family string
		if err := rows.Scan(&id, &osID, &version, &family); err != nil {
			return res, err
		}
		osID, family = strings.ToLower(osID), strings.ToLower(family)
		if osID == "" && family == "" {
			res.Unknown[id] = true
			continue
		}
		listed := slices.ContainsFunc(values, func(v string) bool { return v == osID || v == family })
		if listed == notIn {
			continue
		}
		name := alerting.OSName(osID, version, family)
		res.Matches = append(res.Matches, alerting.Match{
			HostID: id, Title: alerting.OSTitle(name, notIn),
			Details: details(map[string]any{"os": name, "os_id": osID, "os_family": family, "os_version": version}),
		})
	}
	return res, rows.Err()
}

// reboot_required: the newest snapshot (by arrival). When its
// reboot_required collector wasn't ok (failed, skipped, or an agent
// without it) the host is unknown. Payloads without a collectors map come
// from older agents whose fields are all authoritative (PROTOCOL.md).
func evalRebootRequired(ctx context.Context, tx pgx.Tx, _ alerting.Condition, hostIDs []string, _ time.Time) (alerting.Result, error) {
	rows, err := tx.Query(ctx, `
		SELECT h.id::text, s.reboot_required, s.reboot_packages, s.ok
		FROM unnest($1::uuid[]) AS h(id)
		JOIN LATERAL (
		  SELECT reboot_required, reboot_packages,
		         (collector_status IS NULL OR collector_status -> 'reboot_required' ->> 'status' = 'ok') AS ok
		  FROM snapshots WHERE host_id = h.id ORDER BY received_at DESC LIMIT 1
		) s ON true
		ORDER BY 1
	`, hostIDs)
	if err != nil {
		return alerting.Result{}, fmt.Errorf("reboot_required: %w", err)
	}
	defer rows.Close()
	res := alerting.Result{Unknown: map[string]bool{}}
	for rows.Next() {
		var (
			id       string
			required bool
			pkgs     []string
			ok       bool
		)
		if err := rows.Scan(&id, &required, &pkgs, &ok); err != nil {
			return res, err
		}
		switch {
		case !ok:
			res.Unknown[id] = true
		case required:
			d := map[string]any{}
			if len(pkgs) > 0 {
				d["packages"] = pkgs
			}
			res.Matches = append(res.Matches, alerting.Match{HostID: id, Title: alerting.RebootTitle, Details: details(d)})
		}
	}
	return res, rows.Err()
}

// findingJSONSQL is a finding as the notification payload's finding
// object (notify.Finding); f aliases findings.
const findingJSONSQL = `jsonb_build_object(
	'id', f.id, 'kind', f.kind, 'vuln_key', f.vuln_key, 'source_package', f.source_package,
	'packages', to_jsonb(f.packages), 'installed_version', f.installed_version,
	'fixed_version', f.fixed_version, 'fix_channel', f.fix_channel,
	'severity', f.severity, 'severity_rank', f.severity_rank, 'kev', f.is_kev,
	'epss', f.epss_score, 'status', f.status, 'first_seen_at', f.first_seen_at)
	|| CASE WHEN f.image_id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object(
	     'image_id', f.image_id, 'image_refs', to_jsonb(f.image_refs),
	     'containers', to_jsonb(f.container_names)) END`

// vulnerability: open findings of the chosen kinds at or above a severity,
// or in KEV. Subject is the finding's dedup key; details are the finding
// object the notification carries.
func evalVulnerability(ctx context.Context, tx pgx.Tx, c alerting.Condition, hostIDs []string, _ time.Time) (alerting.Result, error) {
	kinds := findings.VulnKinds
	switch c.Options["source"] {
	case "packages":
		kinds = []string{findings.KindVulnerablePackage}
	case "images":
		kinds = []string{findings.KindVulnerableImage}
	}
	kev := c.Operator == "kev"
	rank := alerting.SeverityRanks[c.Enum()]
	rows, err := tx.Query(ctx, `
		SELECT f.host_id::text, f.dedup_key, COALESCE(f.vuln_key, ''), COALESCE(f.source_package, ''),
		       COALESCE(f.severity, ''), f.is_kev, COALESCE(f.image_refs[1], f.image_id, ''),
		       `+findingJSONSQL+`
		FROM findings f
		WHERE f.host_id = ANY ($1::uuid[]) AND f.status = 'open' AND f.kind = ANY ($2::text[])
		  AND CASE WHEN $3 THEN f.is_kev ELSE f.severity_rank >= $4 END
		ORDER BY 1, 2
	`, hostIDs, kinds, kev, rank)
	if err != nil {
		return alerting.Result{}, fmt.Errorf("vulnerability: %w", err)
	}
	var res alerting.Result
	res.Matches, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (alerting.Match, error) {
		var (
			host, key, vuln, pkg, sev, image string
			isKEV                            bool
			finding                          []byte
		)
		if err := r.Scan(&host, &key, &vuln, &pkg, &sev, &isKEV, &image, &finding); err != nil {
			return alerting.Match{}, err
		}
		return alerting.Match{
			HostID: host, Subject: key, Title: alerting.VulnTitle(vuln, pkg, sev, isKEV, image), Details: finding,
		}, nil
	})
	return res, err
}

// host_not_seen: hosts.last_seen_at (set on every snapshot) older than the
// threshold. A host never seen doesn't fire.
func evalHostNotSeen(ctx context.Context, tx pgx.Tx, c alerting.Condition, hostIDs []string, now time.Time) (alerting.Result, error) {
	minutes := c.Int()
	rows, err := tx.Query(ctx, `
		SELECT id::text, last_seen_at FROM hosts
		WHERE id = ANY ($1::uuid[]) AND last_seen_at < $2
		ORDER BY id
	`, hostIDs, now.Add(-time.Duration(minutes)*time.Minute))
	if err != nil {
		return alerting.Result{}, fmt.Errorf("host_not_seen: %w", err)
	}
	var res alerting.Result
	res.Matches, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (alerting.Match, error) {
		var id string
		var seen time.Time
		if err := r.Scan(&id, &seen); err != nil {
			return alerting.Match{}, err
		}
		return alerting.Match{
			HostID: id, Title: alerting.NotSeenTitle(minutes),
			Details: details(map[string]any{"last_seen_at": seen.UTC()}),
		}, nil
	})
	return res, err
}

// collector_failed: collectors with status "error" in the newest snapshot
// (by arrival). A snapshot without a collectors map (older agent) is
// unknown.
func evalCollectorFailed(ctx context.Context, tx pgx.Tx, c alerting.Condition, hostIDs []string, _ time.Time) (alerting.Result, error) {
	rows, err := tx.Query(ctx, `
		SELECT h.id::text, s.collector_status
		FROM unnest($1::uuid[]) AS h(id)
		JOIN LATERAL (
		  SELECT collector_status FROM snapshots WHERE host_id = h.id ORDER BY received_at DESC LIMIT 1
		) s ON true
		ORDER BY 1
	`, hostIDs)
	if err != nil {
		return alerting.Result{}, fmt.Errorf("collector_failed: %w", err)
	}
	defer rows.Close()
	only := c.Strings() // operator "in"; nil for "any"
	res := alerting.Result{Unknown: map[string]bool{}}
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return res, err
		}
		var status map[string]struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		if len(raw) == 0 || json.Unmarshal(raw, &status) != nil || status == nil {
			res.Unknown[id] = true
			continue
		}
		names := make([]string, 0, len(status))
		for name := range status {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			st := status[name]
			if st.Status != "error" || (c.Operator == "in" && !slices.Contains(only, name)) {
				continue
			}
			res.Matches = append(res.Matches, alerting.Match{
				HostID: id, Subject: name, Title: alerting.CollectorTitle(name),
				Details: details(map[string]any{"collector": name, "error": truncate(st.Error, 2000)}),
			})
		}
	}
	return res, rows.Err()
}
