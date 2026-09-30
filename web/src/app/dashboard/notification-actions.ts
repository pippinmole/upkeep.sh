"use server";

import { randomBytes } from "crypto";
import { revalidatePath } from "next/cache";

import { pool } from "@/lib/db";
import {
  ALL_FINDING_KINDS,
  channelType,
  DEDUP_WINDOWS,
  DIGEST_INTERVALS,
  EVENT_TYPES,
  isFindingEvent,
  validateChannelValues,
} from "@/lib/notifiers";
import {
  type CleanSchedule,
  resetsNextRun,
  type ScheduleInput,
  validateSchedule,
} from "@/lib/report-schedules";
import { enqueueAlertDelivery, enqueueReportSendNow } from "@/lib/river";
import { requireAdmin } from "@/lib/viewer";

// Alert rules (/dashboard/alerts), notification channels
// (/dashboard/settings/channels) and report schedules (/dashboard/reports):
// notification_channels,
// alert_rules, alert_rule_channels, report_schedules (except next_run_at /
// last_run_at) and report_schedule_channels are Next.js-owned tables
// (docs/ARCHITECTURE.md "Who owns what"). Every action re-checks the session and the admin role, and
// scopes every statement by workspace_id; ids from the client are never trusted on their own.

export type ActionResult<T = object> =
  | ({ ok: true } & T)
  | { ok: false; error: string; fieldErrors?: Record<string, string> };

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isUuid = (v: unknown): v is string => typeof v === "string" && UUID_RE.test(v);

// Every action here writes (including "Send test" and "Send now", which
// create deliveries), so every one needs an admin; the workspace id scopes
// every statement.
async function adminWorkspaceId(): Promise<string> {
  return (await requireAdmin()).workspaceId;
}

const allowPrivate = () =>
  ["1", "true", "t", "yes"].includes(
    (process.env.SW_NOTIFY_ALLOW_PRIVATE_NETWORKS ?? "").toLowerCase(),
  );

function cleanName(v: unknown): string | null {
  const s = typeof v === "string" ? v.trim() : "";
  return s.length >= 1 && s.length <= 100 ? s : null;
}

// Generated secrets (webhook signing secrets): 32 random bytes.
function generateSecret(): string {
  return `whsec_${randomBytes(32).toString("base64url")}`;
}

// Rules and schedules list their channels, and tests land in the delivery
// log, so every area is refreshed after any change.
function refresh() {
  revalidatePath("/dashboard/alerts", "layout");
  revalidatePath("/dashboard/settings", "layout");
  revalidatePath("/dashboard/reports", "layout");
}

// ---- Channels ----

export type ChannelInput = {
  name: string;
  type: string;
  values: Record<string, string>;
};

export async function createChannel(
  input: ChannelInput,
): Promise<ActionResult<{ id: string; generated: Record<string, string> }>> {
  const workspaceId = await adminWorkspaceId();
  const spec = channelType(String(input?.type));
  if (!spec) return { ok: false, error: "Unknown channel type." };
  const name = cleanName(input.name);
  const v = validateChannelValues(spec, input.values ?? {}, { allowPrivate: allowPrivate() });
  if (!name) v.errors.name = "Name is required (up to 100 characters)";
  if (Object.keys(v.errors).length > 0) {
    return { ok: false, error: "Please fix the highlighted fields.", fieldErrors: v.errors };
  }
  const generated: Record<string, string> = {};
  for (const f of spec.fields) if (f.generated) generated[f.key] = generateSecret();

  const { rows } = await pool.query<{ id: string }>(
    `INSERT INTO notification_channels (workspace_id, name, type, config, secrets)
     VALUES ($1, $2, $3, $4, $5) RETURNING id`,
    [workspaceId, name, spec.type, v.config, { ...v.secrets, ...generated }],
  );
  refresh();
  return { ok: true, id: rows[0].id, generated };
}

export async function updateChannel(
  id: string,
  input: Omit<ChannelInput, "type">,
): Promise<ActionResult> {
  const workspaceId = await adminWorkspaceId();
  if (!isUuid(id)) return { ok: false, error: "Channel not found." };
  const { rows } = await pool.query<{ type: string; secret_keys: string[] }>(
    `SELECT type, ARRAY(SELECT jsonb_object_keys(secrets)) AS secret_keys
     FROM notification_channels WHERE id = $1 AND workspace_id = $2`,
    [id, workspaceId],
  );
  const current = rows[0];
  const spec = current && channelType(current.type);
  if (!current || !spec) return { ok: false, error: "Channel not found." };
  const name = cleanName(input.name);
  const v = validateChannelValues(spec, input.values ?? {}, {
    allowPrivate: allowPrivate(),
    existingSecrets: current.secret_keys,
  });
  if (!name) v.errors.name = "Name is required (up to 100 characters)";
  if (Object.keys(v.errors).length > 0) {
    return { ok: false, error: "Please fix the highlighted fields.", fieldErrors: v.errors };
  }
  // config is replaced; secrets are merged (a blank secret keeps its value,
  // generated ones only change through rotateChannelSecret).
  await pool.query(
    `UPDATE notification_channels
     SET name = $3, config = $4, secrets = secrets || $5::jsonb, updated_at = now()
     WHERE id = $1 AND workspace_id = $2`,
    [id, workspaceId, name, v.config, v.secrets],
  );
  refresh();
  return { ok: true };
}

export async function rotateChannelSecret(
  id: string,
  key: string,
): Promise<ActionResult<{ secret: string }>> {
  const workspaceId = await adminWorkspaceId();
  if (!isUuid(id)) return { ok: false, error: "Channel not found." };
  const { rows } = await pool.query<{ type: string }>(
    `SELECT type FROM notification_channels WHERE id = $1 AND workspace_id = $2`,
    [id, workspaceId],
  );
  const spec = rows[0] && channelType(rows[0].type);
  if (!spec?.fields.some((f) => f.generated && f.key === key)) {
    return { ok: false, error: "This channel has no such generated secret." };
  }
  const secret = generateSecret();
  await pool.query(
    `UPDATE notification_channels SET secrets = secrets || jsonb_build_object($3::text, $4::text), updated_at = now()
     WHERE id = $1 AND workspace_id = $2`,
    [id, workspaceId, key, secret],
  );
  refresh();
  return { ok: true, secret };
}

export async function setChannelEnabled(id: string, enabled: boolean): Promise<ActionResult> {
  const workspaceId = await adminWorkspaceId();
  if (!isUuid(id)) return { ok: false, error: "Channel not found." };
  const r = await pool.query(
    `UPDATE notification_channels SET enabled = $3, updated_at = now() WHERE id = $1 AND workspace_id = $2`,
    [id, workspaceId, enabled === true],
  );
  if (r.rowCount === 0) return { ok: false, error: "Channel not found." };
  refresh();
  return { ok: true };
}

export async function deleteChannel(id: string): Promise<ActionResult> {
  const workspaceId = await adminWorkspaceId();
  if (!isUuid(id)) return { ok: false, error: "Channel not found." };
  // Rule links cascade; the delivery log keeps its rows (channel_id -> NULL).
  const r = await pool.query(
    `DELETE FROM notification_channels WHERE id = $1 AND workspace_id = $2`,
    [id, workspaceId],
  );
  if (r.rowCount === 0) return { ok: false, error: "Channel not found." };
  refresh();
  return { ok: true };
}

export type TestResult = {
  status: "pending" | "retrying" | "delivered" | "failed";
  statusCode: number | null;
  error: string | null;
};

// "Send test": queue a one-attempt test delivery for the worker (the same
// Notifier path real alerts take) and wait briefly for its outcome.
export async function sendTestNotification(id: string): Promise<ActionResult<TestResult>> {
  const workspaceId = await adminWorkspaceId();
  if (!isUuid(id)) return { ok: false, error: "Channel not found." };
  const client = await pool.connect();
  let deliveryId: string;
  try {
    await client.query("BEGIN");
    const ch = await client.query<{ name: string; type: string }>(
      `SELECT name, type FROM notification_channels WHERE id = $1 AND workspace_id = $2`,
      [id, workspaceId],
    );
    if (ch.rowCount === 0) {
      await client.query("ROLLBACK");
      return { ok: false, error: "Channel not found." };
    }
    const n = await client.query<{ id: string }>(
      `INSERT INTO notifications (workspace_id, kind, summary) VALUES ($1, 'test', 'Test notification from upkeep.sh') RETURNING id`,
      [workspaceId],
    );
    const d = await client.query<{ id: string }>(
      `INSERT INTO notification_deliveries (workspace_id, notification_id, channel_id, channel_name, channel_type)
       VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      [workspaceId, n.rows[0].id, id, ch.rows[0].name, ch.rows[0].type],
    );
    deliveryId = d.rows[0].id;
    await enqueueAlertDelivery(client, deliveryId, 1);
    await client.query("COMMIT");
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    throw e;
  } finally {
    client.release();
  }

  // The worker polls every second; a webhook attempt times out after 10s.
  const deadline = Date.now() + 15_000;
  let last: TestResult = { status: "pending", statusCode: null, error: null };
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 500));
    const { rows } = await pool.query<{
      status: TestResult["status"];
      last_status_code: number | null;
      last_error: string | null;
    }>(
      `SELECT status, last_status_code, last_error FROM notification_deliveries WHERE id = $1 AND workspace_id = $2`,
      [deliveryId, workspaceId],
    );
    if (!rows[0]) break;
    last = {
      status: rows[0].status,
      statusCode: rows[0].last_status_code,
      error: rows[0].last_error,
    };
    if (last.status === "delivered" || last.status === "failed") break;
  }
  refresh();
  return { ok: true, ...last };
}

// ---- Rules ----

export type RuleInput = {
  name: string;
  eventTypes: string[];
  minSeverityRank: number;
  kevOnly: boolean;
  findingKinds: string[];
  hostScope: "all" | "selected";
  hostIds: string[];
  channelIds: string[];
  dedupWindowSeconds: number;
  digest: boolean;
  digestIntervalSeconds: number;
};

type CleanRule = Omit<RuleInput, "hostScope" | "hostIds"> & { hostIds: string[] | null };

async function validateRule(
  workspaceId: string,
  input: RuleInput,
): Promise<{ rule?: CleanRule; fieldErrors: Record<string, string> }> {
  const errors: Record<string, string> = {};
  const name = cleanName(input?.name);
  if (!name) errors.name = "Name is required (up to 100 characters)";
  const eventTypes = Array.isArray(input.eventTypes)
    ? [...new Set(input.eventTypes.filter((t) => EVENT_TYPES.includes(t)))]
    : [];
  if (eventTypes.length === 0) errors.eventTypes = "Pick at least one event";
  const minSeverityRank = Number(input.minSeverityRank);
  if (!Number.isInteger(minSeverityRank) || minSeverityRank < 0 || minSeverityRank > 6) {
    errors.minSeverityRank = "Invalid severity";
  }
  // Rules without finding events keep every kind (the column is never empty).
  let findingKinds = Array.isArray(input.findingKinds)
    ? ALL_FINDING_KINDS.filter((k) => input.findingKinds.includes(k))
    : ALL_FINDING_KINDS;
  if (!eventTypes.some(isFindingEvent)) findingKinds = ALL_FINDING_KINDS;
  else if (findingKinds.length === 0) errors.findingKinds = "Pick at least one kind of finding";
  const dedup = Number(input.dedupWindowSeconds);
  if (!DEDUP_WINDOWS.includes(dedup)) errors.dedupWindowSeconds = "Invalid dedup window";
  const interval = Number(input.digestIntervalSeconds);
  if (!DIGEST_INTERVALS.includes(interval)) errors.digestIntervalSeconds = "Invalid interval";

  const channelIds = Array.isArray(input.channelIds)
    ? [...new Set(input.channelIds.filter(isUuid))]
    : [];
  if (channelIds.length === 0) {
    errors.channelIds = "Pick at least one channel";
  } else {
    const { rows } = await pool.query<{ n: string }>(
      `SELECT count(*) AS n FROM notification_channels WHERE workspace_id = $1 AND id = ANY($2::uuid[])`,
      [workspaceId, channelIds],
    );
    if (Number(rows[0].n) !== channelIds.length) errors.channelIds = "Unknown channel";
  }

  let hostIds: string[] | null = null;
  if (input.hostScope === "selected") {
    hostIds = Array.isArray(input.hostIds) ? [...new Set(input.hostIds.filter(isUuid))] : [];
    if (hostIds.length === 0) {
      errors.hostIds = "Pick at least one host, or choose all hosts";
    } else {
      const { rows } = await pool.query<{ n: string }>(
        `SELECT count(*) AS n FROM hosts WHERE workspace_id = $1 AND id = ANY($2::uuid[])`,
        [workspaceId, hostIds],
      );
      if (Number(rows[0].n) !== hostIds.length) errors.hostIds = "Unknown host";
    }
  }
  if (Object.keys(errors).length > 0) return { fieldErrors: errors };
  return {
    fieldErrors: {},
    rule: {
      name: name!,
      eventTypes,
      minSeverityRank,
      kevOnly: input.kevOnly === true,
      findingKinds,
      hostIds,
      channelIds,
      dedupWindowSeconds: dedup,
      digest: input.digest === true,
      digestIntervalSeconds: interval,
    },
  };
}

async function writeRule(
  workspaceId: string,
  id: string | null,
  r: CleanRule,
): Promise<string | null> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const params = [
      workspaceId,
      r.name,
      r.eventTypes,
      r.minSeverityRank,
      r.kevOnly,
      r.hostIds,
      r.dedupWindowSeconds,
      r.digest,
      r.digestIntervalSeconds,
      r.findingKinds,
    ];
    const res = id
      ? await client.query<{ id: string }>(
          `UPDATE alert_rules SET name = $2, event_types = $3, min_severity_rank = $4, kev_only = $5,
                  host_ids = $6, dedup_window_seconds = $7, digest = $8, digest_interval_seconds = $9,
                  finding_kinds = $10, updated_at = now()
           WHERE id = $11 AND workspace_id = $1 RETURNING id`,
          [...params, id],
        )
      : await client.query<{ id: string }>(
          `INSERT INTO alert_rules (workspace_id, name, event_types, min_severity_rank, kev_only, host_ids,
                                    dedup_window_seconds, digest, digest_interval_seconds, finding_kinds)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
          params,
        );
    const ruleId = res.rows[0]?.id;
    if (!ruleId) {
      await client.query("ROLLBACK");
      return null;
    }
    await client.query(`DELETE FROM alert_rule_channels WHERE rule_id = $1 AND workspace_id = $2`, [
      ruleId,
      workspaceId,
    ]);
    // The composite FKs refuse a channel of another user even if the
    // ownership check above were bypassed.
    await client.query(
      `INSERT INTO alert_rule_channels (rule_id, channel_id, workspace_id)
       SELECT $1, unnest($2::uuid[]), $3`,
      [ruleId, r.channelIds, workspaceId],
    );
    await client.query("COMMIT");
    return ruleId;
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

export async function createRule(input: RuleInput): Promise<ActionResult<{ id: string }>> {
  const workspaceId = await adminWorkspaceId();
  const { rule, fieldErrors } = await validateRule(workspaceId, input);
  if (!rule) return { ok: false, error: "Please fix the highlighted fields.", fieldErrors };
  const id = await writeRule(workspaceId, null, rule);
  refresh();
  return id ? { ok: true, id } : { ok: false, error: "Could not create the rule." };
}

export async function updateRule(id: string, input: RuleInput): Promise<ActionResult> {
  const workspaceId = await adminWorkspaceId();
  if (!isUuid(id)) return { ok: false, error: "Rule not found." };
  const { rule, fieldErrors } = await validateRule(workspaceId, input);
  if (!rule) return { ok: false, error: "Please fix the highlighted fields.", fieldErrors };
  const done = await writeRule(workspaceId, id, rule);
  refresh();
  return done ? { ok: true } : { ok: false, error: "Rule not found." };
}

export async function setRuleEnabled(id: string, enabled: boolean): Promise<ActionResult> {
  const workspaceId = await adminWorkspaceId();
  if (!isUuid(id)) return { ok: false, error: "Rule not found." };
  const r = await pool.query(
    `UPDATE alert_rules SET enabled = $3, updated_at = now() WHERE id = $1 AND workspace_id = $2`,
    [id, workspaceId, enabled === true],
  );
  if (r.rowCount === 0) return { ok: false, error: "Rule not found." };
  refresh();
  return { ok: true };
}

export async function deleteRule(id: string): Promise<ActionResult> {
  const workspaceId = await adminWorkspaceId();
  if (!isUuid(id)) return { ok: false, error: "Rule not found." };
  const r = await pool.query(`DELETE FROM alert_rules WHERE id = $1 AND workspace_id = $2`, [
    id,
    workspaceId,
  ]);
  if (r.rowCount === 0) return { ok: false, error: "Rule not found." };
  refresh();
  return { ok: true };
}

// ---- Report schedules ----

const refreshReports = refresh;

async function validateScheduleFor(
  workspaceId: string,
  input: ScheduleInput,
): Promise<{ schedule?: CleanSchedule; fieldErrors: Record<string, string> }> {
  const res = validateSchedule(input);
  if (!res.schedule) return res;
  const { rows } = await pool.query<{ n: string }>(
    `SELECT count(*) AS n FROM notification_channels WHERE workspace_id = $1 AND id = ANY($2::uuid[])`,
    [workspaceId, res.schedule.channelIds],
  );
  if (Number(rows[0].n) !== res.schedule.channelIds.length) {
    return { fieldErrors: { channelIds: "Unknown channel" } };
  }
  return res;
}

// The schedule and its channels in one transaction. next_run_at is the
// worker's: it is NULL on insert and reset to NULL when the timing changes
// or a disabled schedule is enabled (resetsNextRun), so the worker
// recomputes it from now; otherwise neither next_run_at nor last_run_at is
// written here.
async function writeSchedule(
  workspaceId: string,
  id: string | null,
  s: CleanSchedule,
): Promise<string | null> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const params = [
      workspaceId,
      s.name,
      s.enabled,
      s.cadence,
      s.weekday,
      s.dayOfMonth,
      s.hour,
      s.timezone,
    ];
    let reset = false;
    if (id) {
      // Locked so the comparison and the UPDATE see the same row.
      const prev = await client.query<{
        enabled: boolean;
        cadence: CleanSchedule["cadence"];
        weekday: number | null;
        day_of_month: number | null;
        hour: number;
        timezone: string;
      }>(
        `SELECT enabled, cadence, weekday, day_of_month, hour, timezone
         FROM report_schedules WHERE id = $1 AND workspace_id = $2 FOR UPDATE`,
        [id, workspaceId],
      );
      const p = prev.rows[0];
      if (!p) {
        await client.query("ROLLBACK");
        return null;
      }
      reset = resetsNextRun({ ...p, dayOfMonth: p.day_of_month }, s);
    }
    const res = id
      ? await client.query<{ id: string }>(
          `UPDATE report_schedules
           SET name = $2, enabled = $3, cadence = $4, weekday = $5, day_of_month = $6, hour = $7,
               timezone = $8, next_run_at = CASE WHEN $10 THEN NULL ELSE next_run_at END,
               updated_at = now()
           WHERE id = $9 AND workspace_id = $1 RETURNING id`,
          [...params, id, reset],
        )
      : await client.query<{ id: string }>(
          `INSERT INTO report_schedules (workspace_id, name, enabled, cadence, weekday, day_of_month, hour, timezone)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
          params,
        );
    const scheduleId = res.rows[0]?.id;
    if (!scheduleId) {
      await client.query("ROLLBACK");
      return null;
    }
    await client.query(
      `DELETE FROM report_schedule_channels WHERE schedule_id = $1 AND workspace_id = $2`,
      [scheduleId, workspaceId],
    );
    // The composite FKs refuse a channel of another user even if the
    // ownership check above were bypassed.
    await client.query(
      `INSERT INTO report_schedule_channels (schedule_id, channel_id, workspace_id)
       SELECT $1, unnest($2::uuid[]), $3`,
      [scheduleId, s.channelIds, workspaceId],
    );
    await client.query("COMMIT");
    return scheduleId;
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

export async function createReportSchedule(
  input: ScheduleInput,
): Promise<ActionResult<{ id: string }>> {
  const workspaceId = await adminWorkspaceId();
  const { schedule, fieldErrors } = await validateScheduleFor(workspaceId, input);
  if (!schedule) return { ok: false, error: "Please fix the highlighted fields.", fieldErrors };
  const id = await writeSchedule(workspaceId, null, schedule);
  refreshReports();
  return id ? { ok: true, id } : { ok: false, error: "Could not create the schedule." };
}

export async function updateReportSchedule(
  id: string,
  input: ScheduleInput,
): Promise<ActionResult> {
  const workspaceId = await adminWorkspaceId();
  if (!isUuid(id)) return { ok: false, error: "Schedule not found." };
  const { schedule, fieldErrors } = await validateScheduleFor(workspaceId, input);
  if (!schedule) return { ok: false, error: "Please fix the highlighted fields.", fieldErrors };
  const done = await writeSchedule(workspaceId, id, schedule);
  refreshReports();
  return done ? { ok: true } : { ok: false, error: "Schedule not found." };
}

export async function setReportScheduleEnabled(
  id: string,
  enabled: boolean,
): Promise<ActionResult> {
  const workspaceId = await adminWorkspaceId();
  if (!isUuid(id)) return { ok: false, error: "Schedule not found." };
  // Enabling a disabled schedule resets next_run_at (see resetsNextRun);
  // the right-hand side reads the old row. Disabling leaves it alone.
  const r = await pool.query(
    `UPDATE report_schedules
     SET enabled = $3, next_run_at = CASE WHEN $3 AND NOT enabled THEN NULL ELSE next_run_at END,
         updated_at = now()
     WHERE id = $1 AND workspace_id = $2`,
    [id, workspaceId, enabled === true],
  );
  if (r.rowCount === 0) return { ok: false, error: "Schedule not found." };
  refreshReports();
  return { ok: true };
}

export async function deleteReportSchedule(id: string): Promise<ActionResult> {
  const workspaceId = await adminWorkspaceId();
  if (!isUuid(id)) return { ok: false, error: "Schedule not found." };
  // Channel links and past reports cascade; the delivery log keeps its rows
  // (notifications.report_id -> NULL).
  const r = await pool.query(`DELETE FROM report_schedules WHERE id = $1 AND workspace_id = $2`, [
    id,
    workspaceId,
  ]);
  if (r.rowCount === 0) return { ok: false, error: "Schedule not found." };
  refreshReports();
  return { ok: true };
}

// "Send now": queue a real report run (trigger 'manual') for the worker.
// It is stored, delivered to the schedule's channels and becomes the
// previous report for the next comparison. Disabled schedules can still be
// sent by hand. Doesn't wait: building and delivering take a few seconds.
export async function sendReportNow(id: string): Promise<ActionResult> {
  const workspaceId = await adminWorkspaceId();
  if (!isUuid(id)) return { ok: false, error: "Schedule not found." };
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const s = await client.query(
      `SELECT 1 FROM report_schedules WHERE id = $1 AND workspace_id = $2 FOR SHARE`,
      [id, workspaceId],
    );
    if (s.rowCount === 0) {
      await client.query("ROLLBACK");
      return { ok: false, error: "Schedule not found." };
    }
    await enqueueReportSendNow(client, id);
    await client.query("COMMIT");
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    throw e;
  } finally {
    client.release();
  }
  return { ok: true };
}
