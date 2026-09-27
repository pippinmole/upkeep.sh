import { pool } from "./db";

// Plain, uncached reads against tables the Go API owns writes to
// (agents, hosts, snapshots, findings). No caching layer sits in front of
// these yet; if one is added later, Go must call this app's
// /api/revalidate on write, since Next.js's own cache never learns
// about writes made from another process.

// online / stale follow the server's "active" rule (DOMAIN_MODEL.md §4.3
// "As implemented"): stale once silent for more than
// max(3 × push interval, 2 min), interval defaulting to 15 min.
export type AgentStatus = "online" | "stale" | "revoked" | "never";

export type AgentHostRow = {
  hostId: string;
  hostname: string;
  label: string | null;
  osFamily: string | null;
  osId: string | null;
  osVersion: string | null;
  osCodename: string | null;
  kernel: string | null;
  duplicateOf: string | null;
  hostLastSeenAt: string | null;
  mode: "local" | "ssh" | "winrm";
  targetRef: string;
  enabled: boolean;
  lastCollectedAt: string | null;
  // All open findings (any kind) and the most urgent severity among them.
  openFindings: number;
  topSeverity: string | null;
  // Open vulnerable_package findings only, for the vuln pills.
  openVulns: number;
  kevVulns: number;
  topVulnSeverity: string | null;
  // Agent-self-reported, from the host's newest snapshot; may be null.
  publicIpv4: string | null;
  publicIpv6: string | null;
};

export type AgentWithHosts = {
  id: string;
  name: string;
  agentVersion: string | null;
  platform: string | null;
  pushIntervalSeconds: number | null;
  createdAt: string;
  lastSeenAt: string | null;
  revokedAt: string | null;
  status: AgentStatus;
  hosts: AgentHostRow[];
};

type Row = {
  agent_id: string;
  name: string;
  agent_version: string | null;
  platform: string | null;
  push_interval_seconds: number | null;
  created_at: Date;
  last_seen_at: Date | null;
  revoked_at: Date | null;
  status: AgentStatus;
  mode: AgentHostRow["mode"] | null;
  target_ref: string | null;
  enabled: boolean | null;
  last_collected_at: Date | null;
  host_id: string | null;
  hostname: string | null;
  label: string | null;
  os_family: string | null;
  os_id: string | null;
  os_version: string | null;
  os_codename: string | null;
  kernel: string | null;
  duplicate_of: string | null;
  host_last_seen_at: Date | null;
  open_findings: string;
  top_severity: string | null;
  open_vulns: string;
  kev_vulns: string;
  top_vuln_severity: string | null;
  public_ipv4: string | null;
  public_ipv6: string | null;
};

const iso = (d: Date | null) => (d ? d.toISOString() : null);

// One row per (agent, assigned host); an agent that has never pushed has
// no assignment and comes back once with NULL host columns. Scoped by
// agents.user_id; hosts are reached only through that user's agents'
// assignments. Order: active agents first, most recently seen first; the
// local host first under each agent.
export async function getAgentsWithHosts(userId: string): Promise<AgentWithHosts[]> {
  const { rows } = await pool.query<Row>(
    `SELECT a.id AS agent_id, a.name, a.agent_version, a.platform, a.push_interval_seconds,
            a.created_at, a.last_seen_at, a.revoked_at,
            CASE
              WHEN a.revoked_at IS NOT NULL THEN 'revoked'
              WHEN a.last_seen_at IS NULL THEN 'never'
              WHEN now() - a.last_seen_at >
                   make_interval(secs => greatest(3 * coalesce(a.push_interval_seconds, 900), 120))
                THEN 'stale'
              ELSE 'online'
            END AS status,
            ah.mode, ah.target_ref, ah.enabled, ah.last_collected_at,
            h.id AS host_id, h.hostname, h.label, h.os_family, h.os_id, h.os_version,
            h.os_codename, h.kernel, h.duplicate_of, h.last_seen_at AS host_last_seen_at,
            coalesce(f.open_findings, 0) AS open_findings, f.top_severity,
            coalesce(f.open_vulns, 0) AS open_vulns, coalesce(f.kev_vulns, 0) AS kev_vulns,
            f.top_vuln_severity,
            s.public_ipv4, s.public_ipv6
     FROM agents a
     LEFT JOIN agent_hosts ah ON ah.agent_id = a.id
     LEFT JOIN hosts h ON h.id = ah.host_id AND h.user_id = a.user_id
     LEFT JOIN LATERAL (
       SELECT count(*) AS open_findings,
              (array_agg(severity ORDER BY severity_key DESC))[1] AS top_severity,
              count(*) FILTER (WHERE kind = 'vulnerable_package') AS open_vulns,
              count(*) FILTER (WHERE kind = 'vulnerable_package' AND is_kev) AS kev_vulns,
              (array_agg(severity ORDER BY severity_key DESC)
                 FILTER (WHERE kind = 'vulnerable_package'))[1] AS top_vuln_severity
       FROM findings WHERE host_id = h.id AND status = 'open'
     ) f ON h.id IS NOT NULL
     LEFT JOIN LATERAL (
       SELECT sn.public_ipv4, sn.public_ipv6
       FROM snapshots sn
       WHERE sn.host_id = h.id
       ORDER BY sn.collected_at DESC
       LIMIT 1
     ) s ON h.id IS NOT NULL
     WHERE a.user_id = $1
     ORDER BY a.revoked_at IS NOT NULL, a.last_seen_at DESC NULLS LAST, a.id,
              ah.mode <> 'local', h.hostname`,
    [userId],
  );

  const agents: AgentWithHosts[] = [];
  const byId = new Map<string, AgentWithHosts>();
  for (const r of rows) {
    let agent = byId.get(r.agent_id);
    if (!agent) {
      agent = {
        id: r.agent_id,
        name: r.name,
        agentVersion: r.agent_version,
        platform: r.platform,
        pushIntervalSeconds: r.push_interval_seconds,
        createdAt: r.created_at.toISOString(),
        lastSeenAt: iso(r.last_seen_at),
        revokedAt: iso(r.revoked_at),
        status: r.status,
        hosts: [],
      };
      byId.set(r.agent_id, agent);
      agents.push(agent);
    }
    if (r.host_id && r.hostname !== null && r.mode && r.target_ref !== null) {
      agent.hosts.push({
        hostId: r.host_id,
        hostname: r.hostname,
        label: r.label,
        osFamily: r.os_family,
        osId: r.os_id,
        osVersion: r.os_version,
        osCodename: r.os_codename,
        kernel: r.kernel,
        duplicateOf: r.duplicate_of,
        hostLastSeenAt: iso(r.host_last_seen_at),
        mode: r.mode,
        targetRef: r.target_ref,
        enabled: r.enabled ?? true,
        lastCollectedAt: iso(r.last_collected_at),
        openFindings: Number(r.open_findings),
        topSeverity: r.top_severity,
        openVulns: Number(r.open_vulns),
        kevVulns: Number(r.kev_vulns),
        topVulnSeverity: r.top_vuln_severity,
        publicIpv4: r.public_ipv4,
        publicIpv6: r.public_ipv6,
      });
    }
  }
  return agents;
}
