import { pool } from "./db";
import type { MachineAgent, MachineRow } from "./machines";
import { AGENT_STATUS_SQL } from "./queries";

type MachineSqlRow = {
  id: string;
  hostname: string;
  label: string | null;
  os_id: string | null;
  os_version: string | null;
  public_ipv4: string | null;
  public_ipv6: string | null;
  last_seen_at: Date | null;
  archived_at: Date | null;
  reported: boolean | null;
  agents: MachineAgent[] | null;
  crit: string;
  high: string;
  med: string;
  low: string;
  kev: string;
  img_vulns: string;
  img_crit: string;
  img_kev: string;
  img_count: string;
  duplicate_of: string | null;
  duplicate_of_hostname: string | null;
  duplicate_of_label: string | null;
  merged_into: string | null;
  merged_into_hostname: string | null;
  reboot_required: boolean | null;
};

const iso = (d: Date | null) => (d ? d.toISOString() : null);

// Every machine of the workspace, archived ones included (the page offers
// "Show N archived"), with per-severity open vulnerability counts: host
// packages and running container images are counted apart.
export async function getMachines(workspaceId: string): Promise<MachineRow[]> {
  const { rows } = await pool.query<MachineSqlRow>(
    `SELECT h.id, h.hostname, h.label, h.os_id, h.os_version, h.last_seen_at, h.archived_at,
            h.duplicate_of, dh.hostname AS duplicate_of_hostname, dh.label AS duplicate_of_label,
            h.merged_into, mh.hostname AS merged_into_hostname,
            ag.agents,
            coalesce(f.crit, 0) AS crit, coalesce(f.high, 0) AS high,
            coalesce(f.med, 0) AS med, coalesce(f.low, 0) AS low, coalesce(f.kev, 0) AS kev,
            coalesce(img.img_vulns, 0) AS img_vulns, coalesce(img.img_crit, 0) AS img_crit,
            coalesce(img.img_kev, 0) AS img_kev, coalesce(img.img_count, 0) AS img_count,
            s.public_ipv4, s.public_ipv6, s.reboot_required,
            coalesce(s.reported, false) AS reported
     FROM hosts h
     LEFT JOIN hosts dh ON dh.id = h.duplicate_of AND dh.workspace_id = h.workspace_id
     LEFT JOIN hosts mh ON mh.id = h.merged_into AND mh.workspace_id = h.workspace_id
     LEFT JOIN LATERAL (
       SELECT json_agg(json_build_object('id', a.id, 'name', a.name, 'mode', ah.mode,
                                         'status', ${AGENT_STATUS_SQL})
                       ORDER BY a.revoked_at IS NOT NULL, ah.mode <> 'local', ah.mode, a.name) AS agents
       FROM agent_hosts ah
       JOIN agents a ON a.id = ah.agent_id AND a.workspace_id = h.workspace_id
       WHERE ah.host_id = h.id
     ) ag ON true
     LEFT JOIN LATERAL (
       SELECT count(*) FILTER (WHERE severity = 'critical') AS crit,
              count(*) FILTER (WHERE severity = 'high') AS high,
              count(*) FILTER (WHERE severity = 'medium') AS med,
              count(*) FILTER (WHERE severity = 'low') AS low,
              count(*) FILTER (WHERE is_kev) AS kev
       FROM findings
       WHERE host_id = h.id AND status = 'open' AND kind = 'vulnerable_package'
     ) f ON true
     LEFT JOIN LATERAL (
       SELECT count(DISTINCT f.vuln_key) AS img_vulns,
              count(DISTINCT f.vuln_key) FILTER (WHERE f.severity = 'critical') AS img_crit,
              count(DISTINCT f.vuln_key) FILTER (WHERE f.is_kev) AS img_kev,
              count(DISTINCT (f.image_id, f.image_os, f.image_arch, f.image_variant)) AS img_count
       FROM findings f
       WHERE f.host_id = h.id AND f.status = 'open' AND f.kind = 'vulnerable_image'
         AND EXISTS (SELECT 1 FROM host_containers c
                     WHERE c.host_id = h.id AND c.image_id = f.image_id AND c.removed_at IS NULL)
     ) img ON true
     LEFT JOIN LATERAL (
       SELECT sn.public_ipv4, sn.public_ipv6, sn.reboot_required,
              sn.collected_at IS NOT NULL AS reported
       FROM snapshots sn
       WHERE sn.host_id = h.id
       ORDER BY sn.collected_at DESC LIMIT 1   -- snapshots_host_collected_idx
     ) s ON true
     WHERE h.workspace_id = $1
     ORDER BY lower(h.hostname), h.id`,
    [workspaceId],
  );
  return rows.map((r) => ({
    id: r.id,
    hostname: r.hostname,
    label: r.label,
    osId: r.os_id,
    osVersion: r.os_version,
    ip: r.public_ipv4 ?? r.public_ipv6,
    lastSeenAt: iso(r.last_seen_at),
    archivedAt: iso(r.archived_at),
    reported: r.reported ?? false,
    agents: r.agents ?? [],
    vulns: {
      critical: Number(r.crit),
      high: Number(r.high),
      medium: Number(r.med),
      low: Number(r.low),
      kev: Number(r.kev),
    },
    images: {
      vulns: Number(r.img_vulns),
      critical: Number(r.img_crit),
      kev: Number(r.img_kev),
      images: Number(r.img_count),
    },
    duplicateOf:
      r.duplicate_of && r.duplicate_of_hostname !== null
        ? { id: r.duplicate_of, hostname: r.duplicate_of_hostname, label: r.duplicate_of_label }
        : null,
    mergedInto:
      r.merged_into && r.merged_into_hostname !== null
        ? { id: r.merged_into, hostname: r.merged_into_hostname }
        : null,
    rebootRequired: r.reboot_required ?? false,
  }));
}
