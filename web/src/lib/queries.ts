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
  // Agent-self-reported, from its most recent snapshot — best-effort, may
  // be null if the agent couldn't determine a public address for that
  // family. Distinct from the snapshot's server-observed `source_ip`,
  // which this query does not expose (see docs/PROTOCOL.md).
  publicIpv4: string | null;
  publicIpv6: string | null;
};

export async function getHostsForUser(userId: string): Promise<HostSummary[]> {
  const { rows } = await pool.query<{
    id: string;
    hostname: string;
    label: string | null;
    last_seen_at: string | null;
    open_findings: string;
    public_ipv4: string | null;
    public_ipv6: string | null;
  }>(
    `SELECT
       h.id,
       h.hostname,
       h.label,
       h.last_seen_at,
       COUNT(f.id) FILTER (WHERE f.status = 'open') AS open_findings,
       latest.public_ipv4,
       latest.public_ipv6
     FROM hosts h
     LEFT JOIN findings f ON f.host_id = h.id
     LEFT JOIN LATERAL (
       SELECT s.public_ipv4, s.public_ipv6
       FROM snapshots s
       WHERE s.host_id = h.id
       ORDER BY s.collected_at DESC
       LIMIT 1
     ) latest ON true
     WHERE h.user_id = $1
     GROUP BY h.id, latest.public_ipv4, latest.public_ipv6
     ORDER BY h.created_at DESC`,
    [userId],
  );
  return rows.map((r) => ({
    id: r.id,
    hostname: r.hostname,
    label: r.label,
    lastSeenAt: r.last_seen_at,
    openFindings: Number(r.open_findings),
    publicIpv4: r.public_ipv4,
    publicIpv6: r.public_ipv6,
  }));
}
