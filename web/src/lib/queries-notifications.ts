import { pool } from "./db";

// Dashboard reads for Notifications (migration 0009). Every query is
// scoped by user_id. notification_channels.secrets is never selected:
// only which secret keys are set.

export type ChannelRow = {
  id: string;
  name: string;
  type: string;
  config: Record<string, string>;
  secretKeys: string[];
  enabled: boolean;
  createdAt: string;
  ruleCount: number;
  lastStatus: string | null;
  lastDeliveryAt: string | null;
};

export async function getChannels(userId: string): Promise<ChannelRow[]> {
  const { rows } = await pool.query<{
    id: string;
    name: string;
    type: string;
    config: Record<string, string>;
    secret_keys: string[];
    enabled: boolean;
    created_at: Date;
    rule_count: string;
    last_status: string | null;
    last_delivery_at: Date | null;
  }>(
    `SELECT c.id, c.name, c.type, c.config, ARRAY(SELECT jsonb_object_keys(c.secrets)) AS secret_keys,
            c.enabled, c.created_at,
            (SELECT count(*) FROM alert_rule_channels rc WHERE rc.channel_id = c.id) AS rule_count,
            ld.status AS last_status, ld.updated_at AS last_delivery_at
     FROM notification_channels c
     LEFT JOIN LATERAL (
       SELECT d.status, d.updated_at FROM notification_deliveries d
       WHERE d.channel_id = c.id ORDER BY d.created_at DESC LIMIT 1
     ) ld ON true
     WHERE c.user_id = $1
     ORDER BY c.name, c.created_at`,
    [userId],
  );
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    type: r.type,
    config: r.config ?? {},
    secretKeys: r.secret_keys ?? [],
    enabled: r.enabled,
    createdAt: r.created_at.toISOString(),
    ruleCount: Number(r.rule_count),
    lastStatus: r.last_status,
    lastDeliveryAt: r.last_delivery_at?.toISOString() ?? null,
  }));
}

export type RuleRow = {
  id: string;
  name: string;
  enabled: boolean;
  eventTypes: string[];
  minSeverityRank: number;
  kevOnly: boolean;
  hostIds: string[] | null;
  dedupWindowSeconds: number;
  digest: boolean;
  digestIntervalSeconds: number;
  lastDigestAt: string | null;
  createdAt: string;
  channels: { id: string; name: string; enabled: boolean }[];
};

export async function getRules(userId: string): Promise<RuleRow[]> {
  const { rows } = await pool.query<{
    id: string;
    name: string;
    enabled: boolean;
    event_types: string[];
    min_severity_rank: number;
    kev_only: boolean;
    host_ids: string[] | null;
    dedup_window_seconds: number;
    digest: boolean;
    digest_interval_seconds: number;
    last_digest_at: Date | null;
    created_at: Date;
    channels: { id: string; name: string; enabled: boolean }[];
  }>(
    `SELECT r.id, r.name, r.enabled, r.event_types, r.min_severity_rank, r.kev_only,
            r.host_ids::text[] AS host_ids, r.dedup_window_seconds, r.digest,
            r.digest_interval_seconds, r.last_digest_at, r.created_at,
            COALESCE((SELECT json_agg(json_build_object('id', c.id, 'name', c.name, 'enabled', c.enabled) ORDER BY c.name)
                      FROM alert_rule_channels rc JOIN notification_channels c ON c.id = rc.channel_id
                      WHERE rc.rule_id = r.id), '[]') AS channels
     FROM alert_rules r
     WHERE r.user_id = $1
     ORDER BY r.name, r.created_at`,
    [userId],
  );
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    enabled: r.enabled,
    eventTypes: r.event_types,
    minSeverityRank: r.min_severity_rank,
    kevOnly: r.kev_only,
    hostIds: r.host_ids,
    dedupWindowSeconds: r.dedup_window_seconds,
    digest: r.digest,
    digestIntervalSeconds: r.digest_interval_seconds,
    lastDigestAt: r.last_digest_at?.toISOString() ?? null,
    createdAt: r.created_at.toISOString(),
    channels: r.channels,
  }));
}

export type ScopeHost = { id: string; hostname: string; label: string | null };

export async function getScopeHosts(userId: string): Promise<ScopeHost[]> {
  const { rows } = await pool.query<ScopeHost>(
    `SELECT id, hostname, label FROM hosts WHERE user_id = $1 ORDER BY hostname, id`,
    [userId],
  );
  return rows;
}

export type DeliveryAttempt = {
  attempt: number;
  attemptedAt: string;
  statusCode: number | null;
  error: string | null;
  durationMs: number;
};

export type DeliveryRow = {
  id: string;
  createdAt: string;
  updatedAt: string;
  kind: "alert" | "digest" | "test";
  ruleName: string | null;
  summary: string;
  eventCount: number;
  channelId: string | null;
  channelName: string;
  channelType: string;
  status: "pending" | "retrying" | "delivered" | "failed";
  attempts: number;
  lastStatusCode: number | null;
  lastError: string | null;
  attemptLog: DeliveryAttempt[];
};

// The most recent deliveries (the log keeps 90 days; the page shows the
// newest `limit`).
export async function getDeliveries(userId: string, limit = 500): Promise<DeliveryRow[]> {
  const { rows } = await pool.query<{
    id: string;
    created_at: Date;
    updated_at: Date;
    kind: DeliveryRow["kind"];
    rule_name: string | null;
    summary: string;
    event_count: number;
    channel_id: string | null;
    channel_name: string;
    channel_type: string;
    status: DeliveryRow["status"];
    attempts: number;
    last_status_code: number | null;
    last_error: string | null;
    attempt_log: {
      attempt: number;
      attempted_at: string;
      status_code: number | null;
      error: string | null;
      duration_ms: number;
    }[];
  }>(
    `SELECT d.id, d.created_at, d.updated_at, n.kind, r.name AS rule_name, n.summary, n.event_count,
            d.channel_id, d.channel_name, d.channel_type, d.status, d.attempts,
            d.last_status_code, d.last_error,
            COALESCE((SELECT json_agg(json_build_object('attempt', a.attempt, 'attempted_at', a.attempted_at,
                        'status_code', a.status_code, 'error', a.error, 'duration_ms', a.duration_ms) ORDER BY a.attempt)
                      FROM notification_delivery_attempts a WHERE a.delivery_id = d.id), '[]') AS attempt_log
     FROM notification_deliveries d
     JOIN notifications n ON n.id = d.notification_id
     LEFT JOIN alert_rules r ON r.id = n.rule_id
     WHERE d.user_id = $1
     ORDER BY d.created_at DESC, d.id
     LIMIT $2`,
    [userId, limit],
  );
  return rows.map((r) => ({
    id: r.id,
    createdAt: r.created_at.toISOString(),
    updatedAt: r.updated_at.toISOString(),
    kind: r.kind,
    ruleName: r.rule_name,
    summary: r.summary,
    eventCount: r.event_count,
    channelId: r.channel_id,
    channelName: r.channel_name,
    channelType: r.channel_type,
    status: r.status,
    attempts: r.attempts,
    lastStatusCode: r.last_status_code,
    lastError: r.last_error,
    attemptLog: r.attempt_log.map((a) => ({
      attempt: a.attempt,
      attemptedAt: new Date(a.attempted_at).toISOString(),
      statusCode: a.status_code,
      error: a.error,
      durationMs: a.duration_ms,
    })),
  }));
}
