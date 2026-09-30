import type { DataTableServerState } from "@/components/data-table/data-table";

import type { Condition } from "./alert-conditions";
import { ALERT_SORTS, ALERT_STATES, type AlertSort, type AlertState } from "./alerts-table";
import { pool } from "./db";
import { isUuid } from "./queries-inventory";

// Dashboard reads for alert rules and alerts (migration 0024,
// docs/ALERTING.md). Every query here is scoped by the rule's /
// instance's workspace_id, like hosts and channels.

export type AlertRuleRow = {
  id: string;
  name: string;
  enabled: boolean;
  condition: Condition;
  hostIds: string[] | null; // null = all hosts
  notifyOnResolve: boolean;
  digest: boolean;
  digestIntervalSeconds: number;
  isDefault: boolean;
  createdAt: string;
  channels: { id: string; name: string; type: string; enabled: boolean }[];
  firing: number;
};

export async function getAlertRules(workspaceId: string): Promise<AlertRuleRow[]> {
  const { rows } = await pool.query<{
    id: string;
    name: string;
    enabled: boolean;
    condition: Condition;
    host_ids: string[] | null;
    notify_on_resolve: boolean;
    digest: boolean;
    digest_interval_seconds: number;
    is_default: boolean;
    created_at: Date;
    channels: AlertRuleRow["channels"];
    firing: string;
  }>(
    `SELECT r.id, r.name, r.enabled, r.condition, r.host_ids::text[] AS host_ids, r.notify_on_resolve,
            r.digest, r.digest_interval_seconds, r.default_key IS NOT NULL AS is_default, r.created_at,
            COALESCE((SELECT json_agg(json_build_object('id', c.id, 'name', c.name, 'type', c.type,
                                                        'enabled', c.enabled) ORDER BY c.name)
                      FROM alert_rule_channels rc JOIN notification_channels c ON c.id = rc.channel_id
                      WHERE rc.rule_id = r.id), '[]') AS channels,
            (SELECT count(*) FROM alert_instances i WHERE i.rule_id = r.id AND i.state = 'firing') AS firing
     FROM alert_rules r
     WHERE r.workspace_id = $1
     ORDER BY r.name, r.created_at`,
    [workspaceId],
  );
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    enabled: r.enabled,
    condition: r.condition,
    hostIds: r.host_ids,
    notifyOnResolve: r.notify_on_resolve,
    digest: r.digest,
    digestIntervalSeconds: r.digest_interval_seconds,
    isDefault: r.is_default,
    createdAt: r.created_at.toISOString(),
    channels: r.channels,
    firing: Number(r.firing),
  }));
}

export type AlertRow = {
  id: string;
  state: AlertState;
  title: string;
  subject: string;
  property: string;
  ruleId: string | null; // null once the rule is deleted
  ruleName: string;
  hostId: string;
  hostName: string; // label, else hostname
  hostname: string;
  firedAt: string;
  resolvedAt: string | null;
  resolvedReason: string | null;
  details: Record<string, unknown>;
};

export type AlertFilters = {
  q: string | null;
  states: AlertState[] | null;
  ruleIds: string[] | null;
  hostIds: string[] | null;
  sort: { id: AlertSort; desc: boolean };
  page: number;
  pageSize: number;
};

// DataTable state from the URL (tableStateFromParams) -> checked filters.
export function alertFilters(s: DataTableServerState): AlertFilters {
  const values = (id: string) => {
    const f = s.columnFilters.find((c) => c.id === id);
    return Array.isArray(f?.value) ? (f.value as string[]) : null;
  };
  const states = values("state")?.filter((v): v is AlertState =>
    (ALERT_STATES as readonly string[]).includes(v),
  );
  const ruleIds = values("rule")?.filter(isUuid);
  const hostIds = values("host")?.filter(isUuid);
  const sort = s.sorting[0];
  return {
    q: s.globalFilter || null,
    states: states?.length ? states : null,
    ruleIds: ruleIds?.length ? ruleIds : null,
    hostIds: hostIds?.length ? hostIds : null,
    sort:
      sort && (ALERT_SORTS as readonly string[]).includes(sort.id)
        ? { id: sort.id as AlertSort, desc: sort.desc }
        : { id: "state", desc: false },
    page: s.pagination.pageIndex + 1,
    pageSize: s.pagination.pageSize,
  };
}

// One page of the user's alerts (firing and resolved history).
export async function getAlerts(
  workspaceId: string,
  f: AlertFilters,
): Promise<{ rows: AlertRow[]; total: number }> {
  const dir = f.sort.desc ? "DESC" : "ASC";
  // Static ORDER BY variants (allowlisted id and direction).
  const orderBy = {
    state: `i.state ${dir}, i.fired_at DESC, i.id`,
    fired: `i.fired_at ${dir}, i.id`,
    resolved: `i.resolved_at ${dir} NULLS FIRST, i.fired_at DESC, i.id`,
    host: `lower(coalesce(h.label, h.hostname)) ${dir}, i.fired_at DESC, i.id`,
    rule: `lower(i.rule_name) ${dir}, i.fired_at DESC, i.id`,
  }[f.sort.id];
  const { rows } = await pool.query<{
    id: string;
    state: AlertState;
    title: string;
    subject: string;
    property: string;
    rule_id: string | null;
    rule_name: string;
    host_id: string;
    hostname: string;
    label: string | null;
    fired_at: Date;
    resolved_at: Date | null;
    resolved_reason: string | null;
    details: Record<string, unknown>;
    total: string;
  }>(
    `SELECT i.id, i.state, i.title, i.subject, i.property, i.rule_id, i.rule_name, i.host_id,
            h.hostname, h.label, i.fired_at, i.resolved_at, i.resolved_reason, i.details,
            count(*) OVER () AS total
     FROM alert_instances i
     JOIN hosts h ON h.id = i.host_id
     WHERE i.workspace_id = $1
       AND ($2::text IS NULL
            OR strpos(lower(i.title), lower($2)) > 0
            OR strpos(lower(i.rule_name), lower($2)) > 0
            OR strpos(lower(i.subject), lower($2)) > 0
            OR strpos(lower(h.hostname), lower($2)) > 0
            OR strpos(lower(coalesce(h.label, '')), lower($2)) > 0)
       AND ($3::text[] IS NULL OR i.state = ANY($3))
       AND ($4::uuid[] IS NULL OR i.rule_id = ANY($4))
       AND ($5::uuid[] IS NULL OR i.host_id = ANY($5))
     ORDER BY ${orderBy}
     LIMIT $6 OFFSET $7`,
    [workspaceId, f.q, f.states, f.ruleIds, f.hostIds, f.pageSize, (f.page - 1) * f.pageSize],
  );
  return {
    rows: rows.map((r) => ({
      id: r.id,
      state: r.state,
      title: r.title,
      subject: r.subject,
      property: r.property,
      ruleId: r.rule_id,
      ruleName: r.rule_name,
      hostId: r.host_id,
      hostName: r.label || r.hostname,
      hostname: r.hostname,
      firedAt: r.fired_at.toISOString(),
      resolvedAt: r.resolved_at?.toISOString() ?? null,
      resolvedReason: r.resolved_reason,
      details: r.details ?? {},
    })),
    total: Number(rows[0]?.total ?? 0),
  };
}

export type AlertFacets = {
  states: { value: AlertState; count: number }[];
  rules: { id: string; name: string; count: number }[];
  hosts: { id: string; name: string; count: number }[];
};

// Facet options with counts over all of the user's alerts.
export async function getAlertFacets(workspaceId: string): Promise<AlertFacets> {
  const [states, rules, hosts] = await Promise.all([
    pool.query<{ state: AlertState; n: string }>(
      `SELECT state, count(*) AS n FROM alert_instances WHERE workspace_id = $1 GROUP BY state`,
      [workspaceId],
    ),
    pool.query<{ id: string; name: string; n: string }>(
      `SELECT r.id, r.name, count(i.id) AS n
       FROM alert_rules r LEFT JOIN alert_instances i ON i.rule_id = r.id
       WHERE r.workspace_id = $1 GROUP BY r.id ORDER BY r.name`,
      [workspaceId],
    ),
    pool.query<{ id: string; name: string; n: string }>(
      `SELECT h.id, coalesce(h.label, h.hostname) AS name, count(*) AS n
       FROM alert_instances i JOIN hosts h ON h.id = i.host_id
       WHERE i.workspace_id = $1 GROUP BY h.id ORDER BY 2`,
      [workspaceId],
    ),
  ]);
  return {
    states: ALERT_STATES.map((s) => ({
      value: s,
      count: Number(states.rows.find((r) => r.state === s)?.n ?? 0),
    })),
    rules: rules.rows.map((r) => ({ id: r.id, name: r.name, count: Number(r.n) })),
    hosts: hosts.rows.map((r) => ({ id: r.id, name: r.name, count: Number(r.n) })),
  };
}

// Firing alerts on one host (the host page's badge).
export async function getHostFiringAlerts(workspaceId: string, hostId: string): Promise<number> {
  if (!isUuid(hostId)) return 0;
  const { rows } = await pool.query<{ n: string }>(
    `SELECT count(*) AS n FROM alert_instances
     WHERE workspace_id = $1 AND host_id = $2 AND state = 'firing'`,
    [workspaceId, hostId],
  );
  return Number(rows[0]?.n ?? 0);
}
