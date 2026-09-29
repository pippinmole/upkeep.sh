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

export async function getOnboardingState(userId: string): Promise<OnboardingState> {
  const { rows } = await pool.query<{
    agent: boolean;
    host_reported: boolean;
    docker: boolean;
    channel: boolean;
    rule: boolean;
    report: boolean;
  }>(
    `SELECT EXISTS (SELECT 1 FROM agents a WHERE a.user_id = $1) AS agent,
            EXISTS (SELECT 1 FROM hosts h JOIN snapshots s ON s.host_id = h.id
                    WHERE h.user_id = $1) AS host_reported,
            EXISTS (SELECT 1 FROM hosts h JOIN host_docker d ON d.host_id = h.id
                    WHERE h.user_id = $1)
              OR EXISTS (SELECT 1 FROM hosts h JOIN host_containers c ON c.host_id = h.id
                         WHERE h.user_id = $1) AS docker,
            EXISTS (SELECT 1 FROM notification_channels c WHERE c.user_id = $1) AS channel,
            EXISTS (SELECT 1 FROM alert_rules r WHERE r.user_id = $1) AS rule,
            EXISTS (SELECT 1 FROM report_schedules r WHERE r.user_id = $1) AS report`,
    [userId],
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
