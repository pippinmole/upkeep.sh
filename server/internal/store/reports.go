package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/findings"
	"github.com/pippinmole/upkeep.sh/server/internal/reports"
	"github.com/pippinmole/upkeep.sh/server/internal/severity"
)

// Scheduled reports (migration 0017, internal/reports): the reads a report
// is built from. The report_due job runs them in one read transaction
// (BeginReportRead), so every section describes the same instant, then
// builds (reports.Build), compares (reports.Compare with PreviousReport)
// and stores the report in its own write transaction.

// BeginReportRead starts the read-only, REPEATABLE READ transaction a
// report is loaded in: one snapshot of the database for every query.
func (s *Store) BeginReportRead(ctx context.Context) (pgx.Tx, error) {
	return s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
}

// PreviousReport is the latest stored report of a schedule.
type PreviousReport struct {
	ID          string
	GeneratedAt time.Time
	Snapshot    reports.Snapshot
}

// LatestReport returns the schedule's most recent report (scheduled or
// manual: both count as "the previous report"), or nil when it has none.
func (s *Store) LatestReport(ctx context.Context, q pgx.Tx, scheduleID string) (*PreviousReport, error) {
	var (
		p   PreviousReport
		raw []byte
	)
	err := q.QueryRow(ctx, `
		SELECT id::text, generated_at, snapshot FROM reports
		WHERE schedule_id = $1
		ORDER BY generated_at DESC, id DESC LIMIT 1 -- reports_schedule_idx
	`, scheduleID).Scan(&p.ID, &p.GeneratedAt, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &p.Snapshot); err != nil {
		return nil, fmt.Errorf("report %s snapshot: %w", p.ID, err)
	}
	return &p, nil
}

// workspaceHostsSQL restricts to the user's ($1) non-archived hosts, aliased h.
const workspaceHostsSQL = `h.workspace_id = $1 AND h.archived_at IS NULL`

// LoadReportInputs reads one user's estate (non-archived hosts) for
// reports.Build, in tx (see BeginReportRead). period bounds the opened /
// resolved counts (start inclusive, end exclusive), and period.End is the
// instant agent staleness is judged at.
//
// Opened / resolved come from the findings' own timestamps, not from
// alert_events: that outbox only gets rows for users with an enabled rule
// for the event type (hasRuleForSQL), so it would count nothing for a user
// without alert rules. A finding opened in the period has first_seen_at in
// it (kept across reopens); a reopen sets reopened_at; a resolution sets
// resolved_at (cleared on reopen). Each column keeps only the latest
// transition, so a finding that flaps several times within one period
// counts at most one open, one reopen and one resolution.
func (s *Store) LoadReportInputs(ctx context.Context, tx pgx.Tx, workspaceID string, period reports.Period) (reports.Inputs, error) {
	var in reports.Inputs
	var err error
	if in.Hosts, err = loadReportHosts(ctx, tx, workspaceID); err != nil {
		return in, fmt.Errorf("report hosts: %w", err)
	}
	if in.Findings, err = loadReportFindings(ctx, tx, workspaceID); err != nil {
		return in, fmt.Errorf("report findings: %w", err)
	}
	if in.Containers, err = loadReportContainers(ctx, tx, workspaceID); err != nil {
		return in, fmt.Errorf("report containers: %w", err)
	}
	if in.Images, err = loadReportImages(ctx, tx, workspaceID); err != nil {
		return in, fmt.Errorf("report images: %w", err)
	}
	if in.Reboots, err = loadReportReboots(ctx, tx, workspaceID); err != nil {
		return in, fmt.Errorf("report reboots: %w", err)
	}
	if in.StaleAgents, err = loadReportStaleAgents(ctx, tx, workspaceID, period.End); err != nil {
		return in, fmt.Errorf("report stale agents: %w", err)
	}
	if in.HostsWithoutDocker, err = loadReportHostsWithoutDocker(ctx, tx, workspaceID); err != nil {
		return in, fmt.Errorf("report docker coverage: %w", err)
	}
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE f.first_seen_at >= $3 AND f.first_seen_at < $4)
		     + count(*) FILTER (WHERE f.reopened_at >= $3 AND f.reopened_at < $4),
		       count(*) FILTER (WHERE f.status = 'resolved' AND f.resolved_at >= $3 AND f.resolved_at < $4)
		FROM hosts h JOIN findings f ON f.host_id = h.id
		WHERE `+workspaceHostsSQL+` AND f.kind = ANY($2)
		  AND (f.first_seen_at >= $3 OR f.reopened_at >= $3 OR f.resolved_at >= $3)
	`, workspaceID, findings.VulnKinds, period.Start, period.End).Scan(&in.Opened, &in.Resolved); err != nil {
		return in, fmt.Errorf("report transitions: %w", err)
	}
	return in, nil
}

func loadReportHosts(ctx context.Context, tx pgx.Tx, workspaceID string) ([]reports.InputHost, error) {
	rows, err := tx.Query(ctx, `
		SELECT h.id::text, COALESCE(NULLIF(h.label, ''), h.hostname)
		FROM hosts h WHERE `+workspaceHostsSQL+` ORDER BY h.id
	`, workspaceID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (reports.InputHost, error) {
		var h reports.InputHost
		err := r.Scan(&h.ID, &h.Name)
		return h, err
	})
}

// loadReportFindings: open findings of both kinds. The ecosystem, distro
// and release are those of the finding's first binary version (every
// binary of one source package on a host shares them).
func loadReportFindings(ctx context.Context, tx pgx.Tx, workspaceID string) ([]reports.InputFinding, error) {
	rows, err := tx.Query(ctx, `
		SELECT f.host_id::text, f.kind, COALESCE(f.vuln_key, ''), COALESCE(f.source_package, ''),
		       COALESCE(sv.ecosystem, ''), COALESCE(sv.distro, ''), COALESCE(sv.release, ''),
		       f.packages, f.fixed_version, COALESCE(f.fix_channel, ''), f.is_kev, f.severity_rank,
		       f.epss_score::float8, f.first_seen_at,
		       f.image_id, f.image_os, f.image_arch, f.image_variant
		FROM hosts h
		JOIN findings f ON f.host_id = h.id
		LEFT JOIN software_versions sv ON sv.id = f.software_ids[1]
		WHERE `+workspaceHostsSQL+` AND f.status = 'open' AND f.kind = ANY($2)
		ORDER BY f.host_id, f.dedup_key
	`, workspaceID, findings.VulnKinds)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (reports.InputFinding, error) {
		var (
			f                    reports.InputFinding
			rank                 int
			imgID, imgOS, imgArc *string
			imgVariant           *string
		)
		err := r.Scan(&f.HostID, &f.Kind, &f.VulnKey, &f.SourcePackage, &f.Ecosystem, &f.Distro, &f.Release,
			&f.Packages, &f.FixedVersion, &f.FixChannel, &f.KEV, &rank, &f.EPSS, &f.FirstSeenAt,
			&imgID, &imgOS, &imgArc, &imgVariant)
		f.Severity = severity.Bucket(rank)
		if imgID != nil {
			f.Image = &reports.ImageKey{ImageID: *imgID, OS: deref(imgOS), Arch: deref(imgArc), Variant: deref(imgVariant)}
		}
		return f, err
	})
}

// loadReportContainers: current containers with the image key they run
// (the host's current host_images row for the image, once inspected).
func loadReportContainers(ctx context.Context, tx pgx.Tx, workspaceID string) ([]reports.InputContainer, error) {
	rows, err := tx.Query(ctx, `
		SELECT c.host_id::text, c.name, hi.image_id, hi.os, hi.arch, hi.variant
		FROM hosts h
		JOIN host_containers c ON c.host_id = h.id AND c.removed_at IS NULL
		LEFT JOIN host_images hi ON hi.host_id = c.host_id AND hi.image_id = c.image_id
		                        AND hi.removed_at IS NULL AND hi.os IS NOT NULL
		WHERE `+workspaceHostsSQL+`
		ORDER BY c.host_id, c.name, c.container_id
	`, workspaceID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (reports.InputContainer, error) {
		var (
			c                     reports.InputContainer
			id, os, arch, variant *string
		)
		err := r.Scan(&c.HostID, &c.Name, &id, &os, &arch, &variant)
		if id != nil {
			c.Image = &reports.ImageKey{ImageID: *id, OS: deref(os), Arch: deref(arch), Variant: deref(variant)}
		}
		return c, err
	})
}

// loadReportImages: the image keys current containers use, with their
// refs across the user's hosts (repo tags, else repo digests) and why
// their findings are unknown, from image_scores(user): no ok package list
// (its list_status), or an ok list not scored yet ("pending").
func loadReportImages(ctx context.Context, tx pgx.Tx, workspaceID string) ([]reports.InputImage, error) {
	rows, err := tx.Query(ctx, `
		WITH k AS (
			SELECT hi.image_id, hi.os, hi.arch, hi.variant,
			       array_agg(DISTINCT t) FILTER (WHERE t IS NOT NULL AND t <> '<none>:<none>') AS tags,
			       array_agg(DISTINCT d) FILTER (WHERE d IS NOT NULL AND d <> '<none>@<none>') AS digests,
			       bool_or(EXISTS (
			         SELECT 1 FROM host_containers c
			         WHERE c.host_id = hi.host_id AND c.image_id = hi.image_id AND c.removed_at IS NULL
			       )) AS in_use
			FROM hosts h
			JOIN host_images hi ON hi.host_id = h.id AND hi.removed_at IS NULL AND hi.os IS NOT NULL
			LEFT JOIN LATERAL unnest(hi.repo_tags) t ON true
			LEFT JOIN LATERAL unnest(hi.repo_digests) d ON true
			WHERE `+workspaceHostsSQL+`
			GROUP BY 1, 2, 3, 4
		)
		SELECT k.image_id, k.os, k.arch, k.variant, COALESCE(k.tags, '{}'), COALESCE(k.digests, '{}'),
		       CASE WHEN s.list_status IS NULL THEN 'none'
		            WHEN s.list_status <> 'ok' THEN s.list_status
		            WHEN NOT s.scored THEN 'pending'
		            ELSE '' END
		FROM k
		LEFT JOIN image_scores($1) s
		       ON s.image_id = k.image_id AND s.os = k.os AND s.arch = k.arch AND s.variant = k.variant
		WHERE k.in_use
		ORDER BY 1, 2, 3, 4
	`, workspaceID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (reports.InputImage, error) {
		var (
			im            reports.InputImage
			tags, digests []string
		)
		err := r.Scan(&im.Key.ImageID, &im.Key.OS, &im.Key.Arch, &im.Key.Variant, &tags, &digests, &im.NotScored)
		im.Refs = tags
		if len(im.Refs) == 0 {
			im.Refs = digests
		}
		slices.Sort(im.Refs)
		return im, err
	})
}

// loadReportReboots: hosts whose newest snapshot (by collected_at, as the
// overview reads it) has reboot_required, with since = the first snapshot
// of the current run of reboot_required ones.
func loadReportReboots(ctx context.Context, tx pgx.Tx, workspaceID string) ([]reports.InputReboot, error) {
	rows, err := tx.Query(ctx, `
		SELECT h.id::text, s.reboot_packages,
		       (SELECT min(s2.collected_at) FROM snapshots s2
		        WHERE s2.host_id = h.id AND s2.reboot_required
		          AND s2.collected_at > COALESCE((
		              SELECT max(s3.collected_at) FROM snapshots s3
		              WHERE s3.host_id = h.id AND NOT s3.reboot_required), '-infinity'))
		FROM hosts h
		JOIN LATERAL (
			SELECT s.reboot_required, s.reboot_packages FROM snapshots s
			WHERE s.host_id = h.id
			ORDER BY s.collected_at DESC, s.received_at DESC LIMIT 1 -- snapshots_host_collected_idx
		) s ON true
		WHERE `+workspaceHostsSQL+` AND s.reboot_required
		ORDER BY h.id
	`, workspaceID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (reports.InputReboot, error) {
		var rb reports.InputReboot
		err := r.Scan(&rb.HostID, &rb.Packages, &rb.Since)
		return rb, err
	})
}

// loadReportStaleAgents: agents stale at `at` by agent_health's rule (not
// revoked, seen, silent past the active window), with the non-archived
// hosts they collect. Agents with none are left out: nothing in the
// report is missing because of them.
func loadReportStaleAgents(ctx context.Context, tx pgx.Tx, workspaceID string, at time.Time) ([]reports.InputAgent, error) {
	rows, err := tx.Query(ctx, `
		SELECT a.id::text, a.name, a.last_seen_at, array_agg(h.id::text ORDER BY h.id)
		FROM agents a
		JOIN agent_hosts ah ON ah.agent_id = a.id
		JOIN hosts h ON h.id = ah.host_id
		WHERE a.workspace_id = $1 AND `+workspaceHostsSQL+`
		  AND a.revoked_at IS NULL AND a.last_seen_at IS NOT NULL AND `+staleAgentSQL("$2::timestamptz")+`
		GROUP BY a.id
		ORDER BY a.id
	`, workspaceID, at)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (reports.InputAgent, error) {
		var a reports.InputAgent
		err := r.Scan(&a.ID, &a.Name, &a.LastSeenAt, &a.HostIDs)
		return a, err
	})
}

// loadReportHostsWithoutDocker: hosts whose newest snapshot (by
// received_at, as the dashboard's Docker coverage reads it) doesn't have
// docker_images ok: not enabled, engine unavailable, failed, remote, or
// not reported at all.
func loadReportHostsWithoutDocker(ctx context.Context, tx pgx.Tx, workspaceID string) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT h.id::text
		FROM hosts h
		LEFT JOIN LATERAL (
			SELECT s.collector_status FROM snapshots s
			WHERE s.host_id = h.id
			ORDER BY s.received_at DESC LIMIT 1 -- snapshots_host_id_received_at_idx
		) s ON true
		WHERE `+workspaceHostsSQL+`
		  AND COALESCE(s.collector_status->'docker_images'->>'status', 'missing') <> 'ok'
		ORDER BY h.id
	`, workspaceID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
