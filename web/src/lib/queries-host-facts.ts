import { cache } from "react";

import { pool } from "./db";
import { isUuid } from "./queries-inventory";

// Host facts beyond packages (DOMAIN_MODEL.md §4.5, migration 0010):
// services, listeners and local users as validity ranges (open range =
// current), plus the newest snapshot's uptime and facts (unattended-upgrades,
// processes on deleted libraries). Every query is scoped by hosts.user_id;
// callers pass the userId from requireHost().

// When a kind was last confirmed / changed (host_fact_state), or null when
// the collector has never reported ok for this host.
export type FactFreshness = { confirmedAt: string; changedAt: string } | null;

async function freshness(userId: string, hostId: string, kinds: string[]) {
  const { rows } = await pool.query<{ kind: string; confirmed_at: Date; changed_at: Date }>(
    `SELECT st.kind, st.confirmed_at, st.changed_at
     FROM hosts h JOIN host_fact_state st ON st.host_id = h.id
     WHERE h.id = $2 AND h.user_id = $1 AND st.kind = ANY($3::text[])`,
    [userId, hostId, kinds],
  );
  const out: Record<string, FactFreshness> = {};
  for (const k of kinds) out[k] = null;
  for (const r of rows) {
    out[r.kind] = {
      confirmedAt: r.confirmed_at.toISOString(),
      changedAt: r.changed_at.toISOString(),
    };
  }
  return out;
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

export type HostServiceRow = {
  key: string;
  manager: string;
  name: string;
  displayName: string | null;
  startMode: string | null;
  state: string | null;
  runAs: string | null;
  binaryPath: string | null;
  activatedBy: string | null;
  // Since when the service has had exactly this mode/state/etc.
  since: string;
};

export async function getHostServices(userId: string, hostId: string) {
  if (!isUuid(hostId)) return { rows: [] as HostServiceRow[], freshness: null };
  const { rows } = await pool.query<{
    row_key: string;
    manager: string;
    name: string;
    display_name: string | null;
    start_mode: string | null;
    state: string | null;
    run_as: string | null;
    binary_path: string | null;
    activated_by: string | null;
    first_seen_at: Date;
  }>(
    `SELECT s.row_key, s.manager, s.name, s.display_name, s.start_mode, s.state,
            s.run_as, s.binary_path, s.attrs->>'activated_by' AS activated_by, s.first_seen_at
     FROM hosts h
     JOIN host_services s ON s.host_id = h.id AND s.removed_at IS NULL
     WHERE h.id = $2 AND h.user_id = $1
     ORDER BY s.name`,
    [userId, hostId],
  );
  const f = await freshness(userId, hostId, ["services:systemd"]);
  return {
    rows: rows.map(
      (r): HostServiceRow => ({
        key: r.row_key,
        manager: r.manager,
        name: r.name,
        displayName: r.display_name,
        startMode: r.start_mode,
        state: r.state,
        runAs: r.run_as,
        binaryPath: r.binary_path,
        activatedBy: r.activated_by,
        since: r.first_seen_at.toISOString(),
      }),
    ),
    freshness: f["services:systemd"],
  };
}

// ---------------------------------------------------------------------------
// Listeners
// ---------------------------------------------------------------------------

export type HostListenerRow = {
  key: string;
  transport: "tcp" | "udp";
  proto: string;
  localAddr: string;
  port: number;
  processName: string | null;
  // Bound to every interface (0.0.0.0 / ::), not loopback-only etc.
  wildcard: boolean;
  loopback: boolean;
  since: string;
};

const WILDCARDS = new Set(["0.0.0.0", "::"]);
const isLoopback = (a: string) =>
  a.startsWith("127.") || a === "::1" || a.startsWith("::ffff:127.");

export async function getHostListeners(userId: string, hostId: string) {
  if (!isUuid(hostId)) return { rows: [] as HostListenerRow[], freshness: { tcp: null, udp: null } };
  const { rows } = await pool.query<{
    row_key: string;
    transport: "tcp" | "udp";
    proto: string;
    local_addr: string;
    port: number;
    process_name: string | null;
    first_seen_at: Date;
  }>(
    `SELECT l.row_key, l.transport, l.proto, l.local_addr, l.port, l.process_name, l.first_seen_at
     FROM hosts h
     JOIN host_listeners l ON l.host_id = h.id AND l.removed_at IS NULL
     WHERE h.id = $2 AND h.user_id = $1
     ORDER BY l.port, l.proto, l.local_addr`,
    [userId, hostId],
  );
  const f = await freshness(userId, hostId, ["listeners:tcp", "listeners:udp"]);
  return {
    rows: rows.map(
      (r): HostListenerRow => ({
        key: r.row_key,
        transport: r.transport,
        proto: r.proto,
        localAddr: r.local_addr,
        port: r.port,
        processName: r.process_name,
        wildcard: WILDCARDS.has(r.local_addr),
        loopback: isLoopback(r.local_addr),
        since: r.first_seen_at.toISOString(),
      }),
    ),
    freshness: { tcp: f["listeners:tcp"], udp: f["listeners:udp"] },
  };
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

export type HostUserRow = {
  name: string;
  uid: number;
  gid: number;
  home: string | null;
  shell: string | null;
  groups: string[];
  loginShell: boolean;
  admin: boolean;
  since: string;
};

export async function getHostUsers(userId: string, hostId: string) {
  if (!isUuid(hostId)) return { rows: [] as HostUserRow[], freshness: null };
  const { rows } = await pool.query<{
    name: string;
    uid: string;
    gid: string;
    home: string | null;
    shell: string | null;
    groups: string[];
    login_shell: boolean;
    admin: boolean;
    first_seen_at: Date;
  }>(
    `SELECT u.name, u.uid, u.gid, u.home, u.shell, u.groups, u.login_shell, u.admin, u.first_seen_at
     FROM hosts h
     JOIN host_users u ON u.host_id = h.id AND u.removed_at IS NULL
     WHERE h.id = $2 AND h.user_id = $1
     ORDER BY u.uid, u.name`,
    [userId, hostId],
  );
  const f = await freshness(userId, hostId, ["users:local"]);
  return {
    rows: rows.map(
      (r): HostUserRow => ({
        name: r.name,
        uid: Number(r.uid),
        gid: Number(r.gid),
        home: r.home,
        shell: r.shell,
        groups: r.groups,
        loginShell: r.login_shell,
        admin: r.admin,
        since: r.first_seen_at.toISOString(),
      }),
    ),
    freshness: f["users:local"],
  };
}

// ---------------------------------------------------------------------------
// System facts: newest snapshot's uptime + facts, hosts.arch
// ---------------------------------------------------------------------------

// Mirrors server/internal/hostfacts.LinuxFacts (validated on ingest).
export type NeedsRestart = {
  processes: { pid: number; name: string; unit?: string; libraries: string[] }[];
  truncated?: boolean;
  unreadable_processes: number;
};

export type UnattendedUpgrades = {
  package_installed?: boolean;
  update_package_lists?: string;
  unattended_upgrade?: string;
  enabled: boolean;
  last_apt_update?: string;
  last_apt_update_source?: "update-success-stamp" | "lists";
  last_unattended_run?: string;
};

export type HostSystem = {
  arch: string | null;
  // From the newest snapshot by collected_at; null = not reported.
  collectedAt: string | null;
  uptimeSeconds: number | null;
  bootedAt: string | null;
  needsRestart: NeedsRestart | null;
  unattendedUpgrades: UnattendedUpgrades | null;
};

// cache(): the layout's header badges and the overview page share it.
export const getHostSystem = cache(async function getHostSystem(
  userId: string,
  hostId: string,
): Promise<HostSystem | null> {
  if (!isUuid(hostId)) return null;
  const { rows } = await pool.query<{
    arch: string | null;
    collected_at: Date | null;
    uptime_seconds: string | null;
    facts: { needs_restart?: NeedsRestart; unattended_upgrades?: UnattendedUpgrades } | null;
  }>(
    `SELECT h.arch, s.collected_at, s.uptime_seconds, s.facts
     FROM hosts h
     LEFT JOIN LATERAL (
       SELECT collected_at, uptime_seconds, facts FROM snapshots
       WHERE host_id = h.id
       ORDER BY collected_at DESC   -- snapshots_host_collected_idx
       LIMIT 1
     ) s ON true
     WHERE h.id = $2 AND h.user_id = $1`,
    [userId, hostId],
  );
  const r = rows[0];
  if (!r) return null;
  const uptime = r.uptime_seconds === null ? null : Number(r.uptime_seconds);
  return {
    arch: r.arch,
    collectedAt: r.collected_at?.toISOString() ?? null,
    uptimeSeconds: uptime,
    bootedAt:
      uptime !== null && r.collected_at
        ? new Date(r.collected_at.getTime() - uptime * 1000).toISOString()
        : null,
    needsRestart: r.facts?.needs_restart ?? null,
    unattendedUpgrades: r.facts?.unattended_upgrades ?? null,
  };
});

export function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}
