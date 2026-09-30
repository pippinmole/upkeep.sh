import { pool } from "./db";

// First-run progress for the Overview's Getting started checklist
// (docs/design/ux-overhaul.md "Onboarding"): one round trip of EXISTS.
export type OnboardingState = {
  agent: boolean; // an agent enrolled
  hostReported: boolean; // a host has a snapshot
  docker: boolean; // Docker data from any host (optional step)
  channel: boolean;
  rule: boolean;
  report: boolean;
};

export async function getOnboardingState(workspaceId: string): Promise<OnboardingState> {
  const { rows } = await pool.query<{
    agent: boolean;
    host_reported: boolean;
    docker: boolean;
    channel: boolean;
    rule: boolean;
    report: boolean;
  }>(
    `SELECT EXISTS (SELECT 1 FROM agents a WHERE a.workspace_id = $1) AS agent,
            EXISTS (SELECT 1 FROM hosts h JOIN snapshots s ON s.host_id = h.id
                    WHERE h.workspace_id = $1) AS host_reported,
            EXISTS (SELECT 1 FROM hosts h JOIN host_docker d ON d.host_id = h.id
                    WHERE h.workspace_id = $1)
              OR EXISTS (SELECT 1 FROM hosts h JOIN host_containers c ON c.host_id = h.id
                         WHERE h.workspace_id = $1) AS docker,
            EXISTS (SELECT 1 FROM notification_channels c WHERE c.workspace_id = $1) AS channel,
            -- Every workspace starts with a default rule (migration 0024), so
            -- the step is sending one somewhere.
            EXISTS (SELECT 1 FROM alert_rules r JOIN alert_rule_channels rc ON rc.rule_id = r.id
                    WHERE r.workspace_id = $1) AS rule,
            EXISTS (SELECT 1 FROM report_schedules r WHERE r.workspace_id = $1) AS report`,
    [workspaceId],
  );
  const r = rows[0];
  return {
    agent: r.agent,
    hostReported: r.host_reported,
    docker: r.docker,
    channel: r.channel,
    rule: r.rule,
    report: r.report,
  };
}
