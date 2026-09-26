import { pool } from "./db";

// Plain, uncached reads against tables the Go API owns writes to
// (hosts.last_seen_at, snapshots, findings). No caching layer sits in
// front of these yet; if one is added later, Go must call this app's
// /api/revalidate on write, since Next.js's own cache never learns
// about writes made from another process.

export type HostSummary = {
  id: string;
  hostname: string;
  label: string | null;
  lastSeenAt: string | null;
  openFindings: number;
};

export async function getHostsForUser(userId: string): Promise<HostSummary[]> {
  const { rows } = await pool.query<{
    id: string;
    hostname: string;
    label: string | null;
    last_seen_at: string | null;
    open_findings: string;
  }>(
    `SELECT
       h.id,
       h.hostname,
       h.label,
       h.last_seen_at,
       COUNT(f.id) FILTER (WHERE f.status = 'open') AS open_findings
     FROM hosts h
     LEFT JOIN findings f ON f.host_id = h.id
     WHERE h.user_id = $1
     GROUP BY h.id
     ORDER BY h.created_at DESC`,
    [userId],
  );
  return rows.map((r) => ({
    id: r.id,
    hostname: r.hostname,
    label: r.label,
    lastSeenAt: r.last_seen_at,
    openFindings: Number(r.open_findings),
  }));
}
