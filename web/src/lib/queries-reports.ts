import { pool } from "./db";
import type {
  ReportCoverage,
  ReportHeadline,
  ReportSnapshot,
  ReportTrigger,
} from "./report-snapshot";
import type { ScheduleTiming } from "./report-schedules";
import type { ReportSummaryInput } from "./report-summary";

// Dashboard reads for scheduled reports (migration 0017). Every query is
// scoped by user_id. notification_channels.secrets is never selected.
// Listings read only the parts of reports.snapshot they show (headline and
// stale agents, for reportSummary); the report page reads the whole
// snapshot.

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type DeliveryCounts = Record<"pending" | "retrying" | "delivered" | "failed", number>;

export type ScheduleRow = ScheduleTiming & {
  id: string;
  name: string;
  enabled: boolean;
  nextRunAt: string | null;
  lastRunAt: string | null;
  createdAt: string;
  channels: { id: string; name: string; type: string; enabled: boolean }[];
  latestReportId: string | null;
  reportCount: number;
};

export async function getReportSchedules(userId: string): Promise<ScheduleRow[]> {
  const { rows } = await pool.query<{
    id: string;
    name: string;
    enabled: boolean;
    cadence: ScheduleRow["cadence"];
    weekday: number | null;
    day_of_month: number | null;
    hour: number;
    timezone: string;
    next_run_at: Date | null;
    last_run_at: Date | null;
    created_at: Date;
    channels: ScheduleRow["channels"];
    latest_report_id: string | null;
    report_count: string;
  }>(
    `SELECT s.id, s.name, s.enabled, s.cadence, s.weekday, s.day_of_month, s.hour, s.timezone,
            s.next_run_at, s.last_run_at, s.created_at,
            COALESCE((SELECT json_agg(json_build_object('id', c.id, 'name', c.name, 'type', c.type,
                                                        'enabled', c.enabled) ORDER BY c.name)
                      FROM report_schedule_channels sc JOIN notification_channels c ON c.id = sc.channel_id
                      WHERE sc.schedule_id = s.id), '[]') AS channels,
            (SELECT r.id FROM reports r WHERE r.schedule_id = s.id
             ORDER BY r.generated_at DESC LIMIT 1) AS latest_report_id,
            (SELECT count(*) FROM reports r WHERE r.schedule_id = s.id) AS report_count
     FROM report_schedules s
     WHERE s.user_id = $1
     ORDER BY s.name, s.created_at`,
    [userId],
  );
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    enabled: r.enabled,
    cadence: r.cadence,
    weekday: r.weekday,
    dayOfMonth: r.day_of_month,
    hour: r.hour,
    timezone: r.timezone,
    nextRunAt: r.next_run_at?.toISOString() ?? null,
    lastRunAt: r.last_run_at?.toISOString() ?? null,
    createdAt: r.created_at.toISOString(),
    channels: r.channels,
    latestReportId: r.latest_report_id,
    reportCount: Number(r.report_count),
  }));
}

export async function getReportSchedule(
  userId: string,
  scheduleId: string,
): Promise<ScheduleRow | null> {
  if (!UUID_RE.test(scheduleId)) return null;
  // One user's schedules are a handful; reuse the listing's shape.
  const all = await getReportSchedules(userId);
  return all.find((s) => s.id === scheduleId) ?? null;
}

export type PastReportRow = {
  id: string;
  generatedAt: string;
  trigger: ReportTrigger;
  schemaVersion: number;
  summary: ReportSummaryInput;
  deliveries: DeliveryCounts;
};

const DELIVERY_COUNTS_SQL = `
  (SELECT json_build_object(
            'pending', count(*) FILTER (WHERE d.status = 'pending'),
            'retrying', count(*) FILTER (WHERE d.status = 'retrying'),
            'delivered', count(*) FILTER (WHERE d.status = 'delivered'),
            'failed', count(*) FILTER (WHERE d.status = 'failed'))
   FROM notifications n JOIN notification_deliveries d ON d.notification_id = n.id
   WHERE n.report_id = r.id AND n.user_id = r.user_id)`;

// Past reports of one schedule, newest first (reports are kept a year).
export async function getScheduleReports(
  userId: string,
  scheduleId: string,
  limit = 200,
): Promise<PastReportRow[]> {
  if (!UUID_RE.test(scheduleId)) return [];
  const { rows } = await pool.query<{
    id: string;
    generated_at: Date;
    trigger: ReportTrigger;
    schema_version: number | null;
    headline: ReportHeadline;
    stale_agents: ReportCoverage["stale_agents"] | null;
    deliveries: DeliveryCounts;
  }>(
    `SELECT r.id, r.generated_at, r.trigger, (r.snapshot->>'schema_version')::int AS schema_version,
            r.snapshot->'headline' AS headline,
            r.snapshot->'coverage'->'stale_agents' AS stale_agents,
            ${DELIVERY_COUNTS_SQL} AS deliveries
     FROM reports r
     WHERE r.user_id = $1 AND r.schedule_id = $2
     ORDER BY r.generated_at DESC, r.id
     LIMIT $3`,
    [userId, scheduleId, limit],
  );
  return rows.map((r) => ({
    id: r.id,
    generatedAt: r.generated_at.toISOString(),
    trigger: r.trigger,
    schemaVersion: r.schema_version ?? 0,
    summary: { headline: r.headline, coverage: { stale_agents: r.stale_agents ?? [] } },
    deliveries: r.deliveries,
  }));
}

export type ReportDelivery = {
  id: string;
  notificationId: string;
  channelId: string | null;
  channelName: string;
  channelType: string;
  status: keyof DeliveryCounts;
  attempts: number;
  updatedAt: string;
};

export type ReportDetail = {
  id: string;
  scheduleId: string;
  /** The schedule's current name (the snapshot keeps the name at the time). */
  scheduleName: string;
  scheduleTimezone: string;
  generatedAt: string;
  trigger: ReportTrigger;
  /** Unvalidated: check schema_version before reading the rest. */
  snapshot: ReportSnapshot;
  deliveries: ReportDelivery[];
};

// One report, or null when it doesn't exist or isn't the user's.
export async function getReport(userId: string, reportId: string): Promise<ReportDetail | null> {
  if (!UUID_RE.test(reportId)) return null;
  const { rows } = await pool.query<{
    id: string;
    schedule_id: string;
    schedule_name: string;
    schedule_timezone: string;
    generated_at: Date;
    trigger: ReportTrigger;
    snapshot: ReportSnapshot;
    deliveries: {
      id: string;
      notification_id: string;
      channel_id: string | null;
      channel_name: string;
      channel_type: string;
      status: ReportDelivery["status"];
      attempts: number;
      updated_at: string;
    }[];
  }>(
    `SELECT r.id, r.schedule_id, s.name AS schedule_name, s.timezone AS schedule_timezone,
            r.generated_at, r.trigger, r.snapshot,
            COALESCE((SELECT json_agg(json_build_object('id', d.id, 'notification_id', d.notification_id,
                        'channel_id', d.channel_id, 'channel_name', d.channel_name,
                        'channel_type', d.channel_type, 'status', d.status, 'attempts', d.attempts,
                        'updated_at', d.updated_at) ORDER BY d.channel_name, d.created_at)
                      FROM notifications n JOIN notification_deliveries d ON d.notification_id = n.id
                      WHERE n.report_id = r.id AND n.user_id = r.user_id), '[]') AS deliveries
     FROM reports r
     JOIN report_schedules s ON s.id = r.schedule_id AND s.user_id = r.user_id
     WHERE r.id = $1 AND r.user_id = $2`,
    [reportId, userId],
  );
  const r = rows[0];
  if (!r) return null;
  return {
    id: r.id,
    scheduleId: r.schedule_id,
    scheduleName: r.schedule_name,
    scheduleTimezone: r.schedule_timezone,
    generatedAt: r.generated_at.toISOString(),
    trigger: r.trigger,
    snapshot: r.snapshot,
    deliveries: r.deliveries.map((d) => ({
      id: d.id,
      notificationId: d.notification_id,
      channelId: d.channel_id,
      channelName: d.channel_name,
      channelType: d.channel_type,
      status: d.status,
      attempts: d.attempts,
      updatedAt: new Date(d.updated_at).toISOString(),
    })),
  };
}
