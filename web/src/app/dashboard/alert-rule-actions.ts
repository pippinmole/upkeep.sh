"use server";

import { revalidatePath } from "next/cache";
import type { PoolClient } from "pg";

import { type Condition, validateCondition } from "@/lib/alert-conditions";
import { pool } from "@/lib/db";
import { DIGEST_INTERVALS } from "@/lib/notifiers";
import { isUuid } from "@/lib/queries-inventory";
import { enqueueAlertRulesEvaluate } from "@/lib/river";
import { requireAdmin } from "@/lib/viewer";

import type { ActionResult } from "./notification-actions";

// Alert rules (Settings -> Alert rules, docs/ALERTING.md): alert_rules and
// alert_rule_channels are Next.js-owned (docs/ARCHITECTURE.md "Who owns
// what"). Every action writes, so every one needs an admin; the workspace
// id scopes every statement. After a change the worker's
// alert_rules_evaluate is queued in the same transaction, so the Alerts
// page reflects the rule within seconds rather than at the next minute's
// pass.

async function adminWorkspaceId(): Promise<string> {
  return (await requireAdmin()).workspaceId;
}

function refresh() {
  revalidatePath("/dashboard/settings", "layout");
  revalidatePath("/dashboard/alerts", "layout");
  revalidatePath("/dashboard/hosts", "layout");
}

export type RuleInput = {
  name: string;
  condition: Condition;
  hostScope: "all" | "selected";
  hostIds: string[];
  channelIds: string[];
  notifyOnResolve: boolean;
  digest: boolean;
  digestIntervalSeconds: number;
};

type CleanRule = {
  name: string;
  condition: Condition;
  hostIds: string[] | null;
  channelIds: string[];
  notifyOnResolve: boolean;
  digest: boolean;
  digestIntervalSeconds: number;
};

async function validateRule(
  workspaceId: string,
  input: RuleInput,
): Promise<{ rule?: CleanRule; fieldErrors: Record<string, string> }> {
  const errors: Record<string, string> = {};
  const name = typeof input?.name === "string" ? input.name.trim() : "";
  if (name.length < 1 || name.length > 100) errors.name = "Name is required (up to 100 characters)";

  // The worker validates again (internal/alerting) and skips a rule it
  // can't read; the shared vectors keep the two validators identical.
  const cond = validateCondition(input?.condition);
  if (!cond.ok) errors[`condition.${cond.field}`] = cond.message;

  const interval = Number(input?.digestIntervalSeconds);
  if (!DIGEST_INTERVALS.includes(interval)) errors.digestIntervalSeconds = "Invalid interval";

  // No channels is allowed: the rule then only shows alerts in the dashboard.
  const channelIds = Array.isArray(input?.channelIds)
    ? [...new Set(input.channelIds.filter(isUuid))]
    : [];
  if (channelIds.length > 0) {
    const { rows } = await pool.query<{ n: string }>(
      `SELECT count(*) AS n FROM notification_channels WHERE workspace_id = $1 AND id = ANY($2::uuid[])`,
      [workspaceId, channelIds],
    );
    if (Number(rows[0].n) !== channelIds.length) errors.channelIds = "Unknown channel";
  }

  let hostIds: string[] | null = null;
  if (input?.hostScope === "selected") {
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
  if (Object.keys(errors).length > 0 || !cond.ok) return { fieldErrors: errors };
  return {
    fieldErrors: {},
    rule: {
      name,
      condition: cond.condition,
      hostIds,
      channelIds,
      notifyOnResolve: input.notifyOnResolve !== false,
      digest: input.digest === true,
      digestIntervalSeconds: interval,
    },
  };
}

// Runs fn in a transaction that also queues an evaluation pass.
async function withEvaluation<T>(fn: (client: PoolClient) => Promise<T | null>): Promise<T | null> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const out = await fn(client);
    if (out === null) {
      await client.query("ROLLBACK");
      return null;
    }
    await enqueueAlertRulesEvaluate(client);
    await client.query("COMMIT");
    return out;
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

async function writeRule(
  workspaceId: string,
  id: string | null,
  r: CleanRule,
): Promise<string | null> {
  return withEvaluation(async (client) => {
    const params = [
      workspaceId,
      r.name,
      JSON.stringify(r.condition),
      r.hostIds,
      r.notifyOnResolve,
      r.digest,
      r.digestIntervalSeconds,
    ];
    const res = id
      ? await client.query<{ id: string }>(
          `UPDATE alert_rules SET name = $2, condition = $3::jsonb, host_ids = $4, notify_on_resolve = $5,
                  digest = $6, digest_interval_seconds = $7, updated_at = now()
           WHERE id = $8 AND workspace_id = $1 RETURNING id`,
          [...params, id],
        )
      : await client.query<{ id: string }>(
          `INSERT INTO alert_rules (workspace_id, name, condition, host_ids, notify_on_resolve, digest,
                                    digest_interval_seconds)
           VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7) RETURNING id`,
          params,
        );
    const ruleId = res.rows[0]?.id;
    if (!ruleId) return null;
    await client.query(`DELETE FROM alert_rule_channels WHERE rule_id = $1 AND workspace_id = $2`, [
      ruleId,
      workspaceId,
    ]);
    // The composite FKs refuse another workspace's channel even if the
    // ownership check above were bypassed.
    await client.query(
      `INSERT INTO alert_rule_channels (rule_id, channel_id, workspace_id)
       SELECT $1, unnest($2::uuid[]), $3`,
      [ruleId, r.channelIds, workspaceId],
    );
    return ruleId;
  });
}

export async function createAlertRule(input: RuleInput): Promise<ActionResult<{ id: string }>> {
  const workspaceId = await adminWorkspaceId();
  const { rule, fieldErrors } = await validateRule(workspaceId, input);
  if (!rule) return { ok: false, error: "Please fix the highlighted fields.", fieldErrors };
  const id = await writeRule(workspaceId, null, rule);
  refresh();
  return id ? { ok: true, id } : { ok: false, error: "Could not create the rule." };
}

export async function updateAlertRule(id: string, input: RuleInput): Promise<ActionResult> {
  const workspaceId = await adminWorkspaceId();
  if (!isUuid(id)) return { ok: false, error: "Rule not found." };
  const { rule, fieldErrors } = await validateRule(workspaceId, input);
  if (!rule) return { ok: false, error: "Please fix the highlighted fields.", fieldErrors };
  const done = await writeRule(workspaceId, id, rule);
  refresh();
  return done ? { ok: true } : { ok: false, error: "Rule not found." };
}

// Disabling resolves the rule's alerts silently at the next pass.
export async function setAlertRuleEnabled(id: string, enabled: boolean): Promise<ActionResult> {
  const workspaceId = await adminWorkspaceId();
  if (!isUuid(id)) return { ok: false, error: "Rule not found." };
  const done = await withEvaluation(async (client) => {
    const r = await client.query(
      `UPDATE alert_rules SET enabled = $3, updated_at = now() WHERE id = $1 AND workspace_id = $2`,
      [id, workspaceId, enabled === true],
    );
    return r.rowCount ? true : null;
  });
  refresh();
  return done ? { ok: true } : { ok: false, error: "Rule not found." };
}

// The rule's alert history is kept (alert_instances.rule_id -> NULL, the
// name is on each instance); its firing alerts resolve silently at the
// next pass. Pending digest items go with it.
export async function deleteAlertRule(id: string): Promise<ActionResult> {
  const workspaceId = await adminWorkspaceId();
  if (!isUuid(id)) return { ok: false, error: "Rule not found." };
  const done = await withEvaluation(async (client) => {
    const r = await client.query(`DELETE FROM alert_rules WHERE id = $1 AND workspace_id = $2`, [
      id,
      workspaceId,
    ]);
    return r.rowCount ? true : null;
  });
  refresh();
  return done ? { ok: true } : { ok: false, error: "Rule not found." };
}
