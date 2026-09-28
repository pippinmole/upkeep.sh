// The one-line summary of a report: the email subject (here) and the ntfy
// title (server/internal/notify/ntfy, in Go) must produce the same text for
// the same snapshot, so change both together. Parts, in order, each only
// when > 0: urgent actions, to patch this week, images to update, hosts not
// reporting. No parts -> "all clear".

import type { ReportSnapshot } from "@/lib/report-snapshot";

// Same prefix as alert emails (server/internal/notify/email SubjectPrefix).
export const EMAIL_SUBJECT_PREFIX = "[upkeep.sh] ";

function count(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** What the summary reads: listings load only these parts of a snapshot. */
export type ReportSummaryInput = Pick<ReportSnapshot, "headline"> & {
  coverage: Pick<ReportSnapshot["coverage"], "stale_agents">;
};

// Distinct hosts behind the stale agents (an agent can report for more than
// one host, and a host can in principle appear under two agents).
export function staleHostCount(snapshot: ReportSummaryInput): number {
  const ids = new Set<string>();
  for (const agent of snapshot.coverage.stale_agents) {
    for (const host of agent.hosts) ids.add(host.id);
  }
  return ids.size;
}

export function reportSummary(snapshot: ReportSummaryInput): string {
  const h = snapshot.headline;
  const parts: string[] = [];
  if (h.patch_now > 0) parts.push(count(h.patch_now, "urgent action", "urgent actions"));
  if (h.patch_this_week > 0) parts.push(`${h.patch_this_week} to patch this week`);
  if (h.images_to_update > 0) {
    parts.push(count(h.images_to_update, "image to update", "images to update"));
  }
  const staleHosts = staleHostCount(snapshot);
  if (staleHosts > 0) {
    parts.push(count(staleHosts, "host not reporting", "hosts not reporting"));
  } else if (h.stale_agents > 0) {
    // Agents that never enrolled a host still leave the estate unwatched.
    parts.push(count(h.stale_agents, "agent not reporting", "agents not reporting"));
  }
  return parts.length > 0 ? parts.join(", ") : "all clear";
}

/** "{schedule name}: {summary}", the ntfy title. */
export function reportTitle(snapshot: ReportSnapshot): string {
  return `${snapshot.schedule.name}: ${reportSummary(snapshot)}`;
}

export function reportEmailSubject(snapshot: ReportSnapshot): string {
  return EMAIL_SUBJECT_PREFIX + reportTitle(snapshot);
}
