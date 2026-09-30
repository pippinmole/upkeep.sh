import { pool } from "./db";
import type { ReportCoverage, ReportHeadline, ReportTrigger } from "./report-snapshot";
import type { ReportSummaryInput } from "./report-summary";

// The Overview page's estate health, "Needs attention" signals and latest
// report (docs/design/ux-overhaul.md "Overview (redesigned)"). Vulnerability
// numbers stay in queries-vulns.ts / queries-overview-images.ts.

// Worst first: the order the health grid and "Needs attention" rank by.
export type HostHealthState = "kev" | "critical" | "reboot" | "stale" | "waiting" | "ok";

export type HostHealth = {
  id: string;
  name: string; // label, else hostname
  state: HostHealthState;
  reported: boolean; // has at least one snapshot
  stale: boolean;
  reboot: boolean;
  kev: number; // open KEV host package findings
  critical: number; // open critical host package findings
};

export type EstateSignals = {
  containers: number; // current containers on non-archived hosts
  images: number; // distinct current image ids
  criticalImages: number; // image keys with an open critical vulnerable_image finding
  failedDeliveries: number; // notification deliveries failed in the last 7 days
  neverConnected: string[]; // names of non-revoked agents that never pushed
};

export type EstateHealth = { hosts: HostHealth[]; signals: EstateSignals };

// "Stale" is the agent-health rule (lib/queries.ts AGENT_STATUS_SQL), so the
// Overview and the Agents page agree: a host is stale when none of its
// enabled, non-revoked agents is online. Reboot comes from the newest
// snapshot, as in getOverviewStats.
export async function getEstateHealth(workspaceId: string): Promise<EstateHealth> {
  const [hosts, signals] = await Promise.all([
    pool.query<{
      id: string;
      name: string;
      reported: boolean;
      reboot: boolean;
      stale: boolean;
      kev: string;
      critical: string;
    }>(
      `SELECT h.id, coalesce(h.label, h.hostname) AS name,
              s.reboot_required IS NOT NULL AS reported,
              coalesce(s.reboot_required, false) AS reboot,
              NOT EXISTS (
                SELECT 1
                FROM agent_hosts ah
                JOIN agents a ON a.id = ah.agent_id AND a.workspace_id = h.workspace_id
                WHERE ah.host_id = h.id AND ah.enabled AND a.revoked_at IS NULL
                  AND now() - a.last_seen_at <=
                      make_interval(secs => greatest(3 * coalesce(a.push_interval_seconds, 900), 120))
              ) AS stale,
              f.kev, f.critical
       FROM hosts h
       LEFT JOIN LATERAL (
         SELECT sn.reboot_required FROM snapshots sn
         WHERE sn.host_id = h.id
         ORDER BY sn.collected_at DESC LIMIT 1   -- snapshots_host_collected_idx
       ) s ON true
       LEFT JOIN LATERAL (
         SELECT count(*) FILTER (WHERE fi.is_kev) AS kev,
                count(*) FILTER (WHERE fi.severity = 'critical') AS critical
         FROM findings fi
         WHERE fi.host_id = h.id AND fi.status = 'open' AND fi.kind = 'vulnerable_package'
       ) f ON true
       WHERE h.workspace_id = $1 AND h.archived_at IS NULL
       ORDER BY lower(coalesce(h.label, h.hostname)), h.id`,
      [workspaceId],
    ),
    pool.query<{
      containers: string;
      images: string;
      critical_images: string;
      failed_deliveries: string;
      never_agents: string[] | null;
    }>(
      `SELECT
         (SELECT count(*) FROM hosts h
          JOIN host_containers c ON c.host_id = h.id AND c.removed_at IS NULL
          WHERE h.workspace_id = $1 AND h.archived_at IS NULL) AS containers,
         (SELECT count(DISTINCT hi.image_id) FROM hosts h
          JOIN host_images hi ON hi.host_id = h.id AND hi.removed_at IS NULL
          WHERE h.workspace_id = $1 AND h.archived_at IS NULL) AS images,
         (SELECT count(DISTINCT concat_ws('|', f.image_id, f.image_os, f.image_arch, f.image_variant))
          FROM hosts h
          JOIN findings f ON f.host_id = h.id
          WHERE h.workspace_id = $1 AND h.archived_at IS NULL AND f.kind = 'vulnerable_image'
            AND f.status = 'open' AND f.severity = 'critical') AS critical_images,
         (SELECT count(*) FROM notification_deliveries d
          WHERE d.workspace_id = $1 AND d.status = 'failed'
            AND d.created_at > now() - interval '7 days') AS failed_deliveries,
         (SELECT array_agg(a.name ORDER BY a.created_at) FROM agents a
          WHERE a.workspace_id = $1 AND a.revoked_at IS NULL AND a.last_seen_at IS NULL) AS never_agents`,
      [workspaceId],
    ),
  ]);

  const s = signals.rows[0];
  return {
    hosts: hosts.rows.map((r) => {
      const kev = Number(r.kev);
      const critical = Number(r.critical);
      const state: HostHealthState =
        kev > 0
          ? "kev"
          : critical > 0
            ? "critical"
            : r.reboot
              ? "reboot"
              : r.stale
                ? "stale"
                : !r.reported
                  ? "waiting"
                  : "ok";
      return {
        id: r.id,
        name: r.name,
        state,
        reported: r.reported,
        stale: r.stale,
        reboot: r.reboot,
        kev,
        critical,
      };
    }),
    signals: {
      containers: Number(s?.containers ?? 0),
      images: Number(s?.images ?? 0),
      criticalImages: Number(s?.critical_images ?? 0),
      failedDeliveries: Number(s?.failed_deliveries ?? 0),
      neverConnected: s?.never_agents ?? [],
    },
  };
}

export type LatestReport = {
  id: string;
  scheduleName: string; // the schedule's current name
  generatedAt: string;
  trigger: ReportTrigger;
  summary: ReportSummaryInput;
};

// The user's newest report of any schedule, reading only the snapshot parts
// the card shows (as the report listings do).
export async function getLatestReport(workspaceId: string): Promise<LatestReport | null> {
  const { rows } = await pool.query<{
    id: string;
    name: string;
    generated_at: Date;
    trigger: ReportTrigger;
    headline: ReportHeadline;
    stale_agents: ReportCoverage["stale_agents"] | null;
  }>(
    `SELECT r.id, s.name, r.generated_at, r.trigger,
            r.snapshot->'headline' AS headline,
            r.snapshot->'coverage'->'stale_agents' AS stale_agents
     FROM reports r
     JOIN report_schedules s ON s.id = r.schedule_id AND s.workspace_id = r.workspace_id
     WHERE r.workspace_id = $1
     ORDER BY r.generated_at DESC, r.id
     LIMIT 1   -- reports_workspace_idx`,
    [workspaceId],
  );
  const r = rows[0];
  if (!r) return null;
  return {
    id: r.id,
    scheduleName: r.name,
    generatedAt: r.generated_at.toISOString(),
    trigger: r.trigger,
    summary: { headline: r.headline, coverage: { stale_agents: r.stale_agents ?? [] } },
  };
}
