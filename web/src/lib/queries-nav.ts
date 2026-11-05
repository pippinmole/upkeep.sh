import { cache } from "react";

import type { TopBarData } from "@/components/layout/types";

import { pool } from "./db";

// The top bar's data in one round trip (the dashboard layout reads it on
// each server render).
// - workspaceName: the workspace's name, "" if the row is missing.
// - firingAlerts: alert instances firing now on active hosts.
// - hasSwarm: as queries-docker-fleet.ts hasSwarm.
export const getTopBarData = cache(async function getTopBarData(
  workspaceId: string,
): Promise<TopBarData> {
  const { rows } = await pool.query<{
    workspace_name: string | null;
    firing_alerts: string;
    has_swarm: boolean;
  }>(
    `SELECT
       (SELECT name FROM workspaces WHERE id = $1) AS workspace_name,
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
    workspaceName: r?.workspace_name ?? "",
    firingAlerts: Number(r?.firing_alerts ?? 0),
    hasSwarm: r?.has_swarm ?? false,
  };
});
