import { cache } from "react";

import type { NavCounts } from "@/components/layout/types";

import { pool } from "./db";
import { AGENT_STATUS_SQL } from "./queries";

// The sidebar's "needs action" badges and the Swarm switch, in one round
// trip (the dashboard layout reads it on each server render).
// - vulnsUrgent: distinct vulnerabilities with an open finding that is in
//   KEV or critical (findings.severity, as Go assessed it) on an active host,
//   in host packages only: one badge can't show two kinds, and host package
//   and image counts are never summed (DOMAIN_MODEL.md §3.6). Urgent images
//   have their own Overview "Needs attention" item.
// - staleHosts: active hosts whose agents, the revoked ones aside, are none
//   of them online: the agent status rule of the Agents and Hosts pages.
// - staleAgents: agents that went quiet or never reported, not revoked.
// - firingAlerts: alert instances firing now on active hosts.
// - hasSwarm: as queries-docker-fleet.ts hasSwarm.
export const getNavCounts = cache(async function getNavCounts(
  workspaceId: string,
): Promise<NavCounts> {
  const { rows } = await pool.query<{
    vulns_urgent: string;
    stale_hosts: string;
    stale_agents: string;
    firing_alerts: string;
    has_swarm: boolean;
  }>(
    `WITH agent_status AS (
       SELECT a.id, ${AGENT_STATUS_SQL} AS status FROM agents a WHERE a.workspace_id = $1
     ), host_agents AS (
       SELECT ah.host_id,
              bool_or(s.status = 'online') AS any_online,
              bool_or(s.status <> 'revoked') AS any_active
       FROM agent_hosts ah JOIN agent_status s ON s.id = ah.agent_id
       GROUP BY ah.host_id
     )
     SELECT
       (SELECT count(DISTINCT f.vuln_key)
        FROM hosts h JOIN findings f ON f.host_id = h.id
        WHERE h.workspace_id = $1 AND h.archived_at IS NULL
          AND f.kind = 'vulnerable_package' AND f.status = 'open'
          AND (f.is_kev OR f.severity = 'critical')) AS vulns_urgent,
       (SELECT count(*)
        FROM hosts h JOIN host_agents ha ON ha.host_id = h.id
        WHERE h.workspace_id = $1 AND h.archived_at IS NULL
          AND ha.any_active AND NOT ha.any_online) AS stale_hosts,
       (SELECT count(*) FROM agent_status WHERE status IN ('stale', 'never')) AS stale_agents,
       (SELECT count(*) FROM alert_instances ai JOIN hosts h ON h.id = ai.host_id
        WHERE ai.workspace_id = $1 AND ai.state = 'firing' AND h.archived_at IS NULL) AS firing_alerts,
       EXISTS (SELECT 1 FROM swarm_clusters sc WHERE sc.workspace_id = $1)
         OR EXISTS (SELECT 1 FROM hosts h JOIN host_docker hd ON hd.host_id = h.id
                    WHERE h.workspace_id = $1 AND h.archived_at IS NULL
                      AND hd.swarm_state IS NOT NULL) AS has_swarm`,
    [workspaceId],
  );
  const r = rows[0];
  return {
    vulnsUrgent: Number(r?.vulns_urgent ?? 0),
    staleHosts: Number(r?.stale_hosts ?? 0),
    staleAgents: Number(r?.stale_agents ?? 0),
    firingAlerts: Number(r?.firing_alerts ?? 0),
    hasSwarm: r?.has_swarm ?? false,
  };
});
