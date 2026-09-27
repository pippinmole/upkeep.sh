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

// AgentStatus of an agents row aliased "a".
const AGENT_STATUS_SQL = `CASE
    WHEN a.revoked_at IS NOT NULL THEN 'revoked'
    WHEN a.last_seen_at IS NULL THEN 'never'
    WHEN now() - a.last_seen_at >
         make_interval(secs => greatest(3 * coalesce(a.push_interval_seconds, 900), 120))
      THEN 'stale'
    ELSE 'online'
  END`;

// Open findings of a host aliased "h" (LATERAL): all kinds, and
// vulnerable_package only for the vuln pills.
const HOST_FINDINGS_SQL = `SELECT count(*) AS open_findings,
         (array_agg(severity ORDER BY severity_key DESC))[1] AS top_severity,
         count(*) FILTER (WHERE kind = 'vulnerable_package') AS open_vulns,
         count(*) FILTER (WHERE kind = 'vulnerable_package' AND is_kev) AS kev_vulns,
         (array_agg(severity ORDER BY severity_key DESC)
            FILTER (WHERE kind = 'vulnerable_package'))[1] AS top_vuln_severity
  FROM findings WHERE host_id = h.id AND status = 'open'`;

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
  archivedAt: string | null;
  mergedInto: string | null;
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
  // Dashboard "Rotate credentials" pending until the agent rotates.
  rotateRequestedAt: string | null;
  // Current secret issued at (last rotation, else enrollment).
  credentialIssuedAt: string | null;
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
  rotate_requested_at: Date | null;
  credential_issued_at: Date | null;
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
  archived_at: Date | null;
  merged_into: string | null;
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
            ${AGENT_STATUS_SQL} AS status,
            c.rotate_requested_at, coalesce(c.rotated_at, c.created_at) AS credential_issued_at,
            ah.mode, ah.target_ref, ah.enabled, ah.last_collected_at,
            h.id AS host_id, h.hostname, h.label, h.os_family, h.os_id, h.os_version,
            h.os_codename, h.kernel, h.duplicate_of, h.archived_at, h.merged_into,
            h.last_seen_at AS host_last_seen_at,
            coalesce(f.open_findings, 0) AS open_findings, f.top_severity,
            coalesce(f.open_vulns, 0) AS open_vulns, coalesce(f.kev_vulns, 0) AS kev_vulns,
            f.top_vuln_severity,
            s.public_ipv4, s.public_ipv6
     FROM agents a
     LEFT JOIN agent_credentials c ON c.agent_id = a.id
     LEFT JOIN agent_hosts ah ON ah.agent_id = a.id
     LEFT JOIN hosts h ON h.id = ah.host_id AND h.user_id = a.user_id
     LEFT JOIN LATERAL (${HOST_FINDINGS_SQL}) f ON h.id IS NOT NULL
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
        rotateRequestedAt: iso(r.rotate_requested_at),
        credentialIssuedAt: iso(r.credential_issued_at),
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
        archivedAt: iso(r.archived_at),
        mergedInto: r.merged_into,
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

export type HostAgent = {
  id: string;
  name: string;
  mode: AgentHostRow["mode"];
  status: AgentStatus;
};

export type HostListRow = {
  id: string;
  hostname: string;
  label: string | null;
  osFamily: string | null;
  osId: string | null;
  osVersion: string | null;
  osCodename: string | null;
  kernel: string | null;
  // Possible duplicate of this host (same machine identity), if flagged.
  duplicateOf: { id: string; hostname: string; label: string | null } | null;
  archivedAt: string | null;
  mergedInto: { id: string; hostname: string } | null;
  createdAt: string;
  lastSeenAt: string | null;
  agents: HostAgent[];
  openFindings: number;
  topSeverity: string | null;
  openVulns: number;
  kevVulns: number;
  topVulnSeverity: string | null;
};

type HostRow = {
  id: string;
  hostname: string;
  label: string | null;
  os_family: string | null;
  os_id: string | null;
  os_version: string | null;
  os_codename: string | null;
  kernel: string | null;
  duplicate_of: string | null;
  duplicate_of_hostname: string | null;
  duplicate_of_label: string | null;
  archived_at: Date | null;
  merged_into: string | null;
  merged_into_hostname: string | null;
  created_at: Date;
  last_seen_at: Date | null;
  agents: HostAgent[] | null;
  open_findings: string;
  top_severity: string | null;
  open_vulns: string;
  kev_vulns: string;
  top_vuln_severity: string | null;
};

// Every host of the user, archived ones included (the Hosts page filters
// them client-side), with the agents that collect it. Scoped by
// hosts.user_id; joined agents and hosts are the same user's.
export async function getHosts(userId: string): Promise<HostListRow[]> {
  const { rows } = await pool.query<HostRow>(
    `SELECT h.id, h.hostname, h.label, h.os_family, h.os_id, h.os_version, h.os_codename,
            h.kernel, h.duplicate_of, dh.hostname AS duplicate_of_hostname,
            dh.label AS duplicate_of_label, h.archived_at, h.merged_into,
            mh.hostname AS merged_into_hostname, h.created_at, h.last_seen_at,
            ag.agents,
            coalesce(f.open_findings, 0) AS open_findings, f.top_severity,
            coalesce(f.open_vulns, 0) AS open_vulns, coalesce(f.kev_vulns, 0) AS kev_vulns,
            f.top_vuln_severity
     FROM hosts h
     LEFT JOIN hosts dh ON dh.id = h.duplicate_of AND dh.user_id = h.user_id
     LEFT JOIN hosts mh ON mh.id = h.merged_into AND mh.user_id = h.user_id
     LEFT JOIN LATERAL (
       SELECT json_agg(json_build_object('id', a.id, 'name', a.name, 'mode', ah.mode,
                                         'status', ${AGENT_STATUS_SQL})
                       ORDER BY a.revoked_at IS NOT NULL, ah.mode <> 'local', a.name) AS agents
       FROM agent_hosts ah
       JOIN agents a ON a.id = ah.agent_id AND a.user_id = h.user_id
       WHERE ah.host_id = h.id
     ) ag ON true
     LEFT JOIN LATERAL (${HOST_FINDINGS_SQL}) f ON true
     WHERE h.user_id = $1
     ORDER BY h.archived_at IS NOT NULL, h.last_seen_at DESC NULLS LAST, h.hostname, h.id`,
    [userId],
  );
  return rows.map((r) => ({
    id: r.id,
    hostname: r.hostname,
    label: r.label,
    osFamily: r.os_family,
    osId: r.os_id,
    osVersion: r.os_version,
    osCodename: r.os_codename,
    kernel: r.kernel,
    duplicateOf:
      r.duplicate_of && r.duplicate_of_hostname !== null
        ? { id: r.duplicate_of, hostname: r.duplicate_of_hostname, label: r.duplicate_of_label }
        : null,
    archivedAt: iso(r.archived_at),
    mergedInto:
      r.merged_into && r.merged_into_hostname !== null
        ? { id: r.merged_into, hostname: r.merged_into_hostname }
        : null,
    createdAt: r.created_at.toISOString(),
    lastSeenAt: iso(r.last_seen_at),
    agents: r.agents ?? [],
    openFindings: Number(r.open_findings),
    topSeverity: r.top_severity,
    openVulns: Number(r.open_vulns),
    kevVulns: Number(r.kev_vulns),
    topVulnSeverity: r.top_vuln_severity,
  }));
}
