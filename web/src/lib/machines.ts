// Types and pure helpers for the Machines home page.

import { osLabel } from "./os";
import { oneOf, param, type SearchParams } from "./search-params";

export type AgentStatus = "online" | "stale" | "never" | "revoked";
export type MachineAgent = {
  id: string;
  name: string;
  mode: "local" | "ssh" | "winrm";
  status: AgentStatus;
};
export type MachineStatus = "online" | "stale" | "never";
export type SeverityCounts = { critical: number; high: number; medium: number; low: number };

export type MachineRow = {
  id: string;
  hostname: string;
  label: string | null;
  osId: string | null;
  osVersion: string | null;
  ip: string | null; // latest snapshot public_ipv4, else public_ipv6
  lastSeenAt: string | null;
  archivedAt: string | null;
  reported: boolean; // any snapshot exists
  agents: MachineAgent[]; // non-revoked first, then local, ssh, winrm, then name
  vulns: SeverityCounts & { kev: number }; // host packages only
  images: { vulns: number; critical: number; kev: number; images: number }; // running images only
  duplicateOf: { id: string; hostname: string; label: string | null } | null;
  mergedInto: { id: string; hostname: string } | null;
  rebootRequired: boolean;
};

// True when the machine has agents but every one is revoked.
export function hasNoActiveAgent(agents: MachineAgent[]): boolean {
  return agents.length > 0 && agents.every((a) => a.status === "revoked");
}

export function machineStatus(agents: MachineAgent[]): MachineStatus {
  if (agents.some((a) => a.status === "online")) return "online";
  if (hasNoActiveAgent(agents)) return "stale";
  return agents.some((a) => a.status === "stale") ? "stale" : "never";
}

// The collector shown on a machine row: the first non-revoked agent (else the
// first agent) and how many other non-revoked agents also collect it.
export function collectorLabel(agents: MachineAgent[]): { text: string; more: number } | null {
  if (agents.length === 0) return null;
  const active = agents.filter((a) => a.status !== "revoked");
  const first = active[0] ?? agents[0];
  return {
    text: first.mode === "local" ? "Local agent" : `via ${first.name}`,
    more: active.filter((a) => a !== first).length,
  };
}

export type MachineFilters = {
  q: string | null;
  status: MachineStatus | null;
  os: string | null;
  critical: boolean;
  kev: boolean;
  archived: boolean;
};

const STATUSES = ["online", "stale", "never"] as const;

export function parseMachineFilters(sp: SearchParams): MachineFilters {
  return {
    q: param(sp, "q"),
    status: oneOf(sp, "status", STATUSES),
    os: param(sp, "os"),
    critical: param(sp, "critical") === "1",
    kev: param(sp, "kev") === "1",
    archived: param(sp, "archived") === "1",
  };
}

export function hasCritical(m: MachineRow): boolean {
  return m.vulns.critical > 0 || m.images.critical > 0;
}

export function hasKev(m: MachineRow): boolean {
  return m.vulns.kev > 0 || m.images.kev > 0;
}

function matchesQuery(m: MachineRow, q: string): boolean {
  const needle = q.toLowerCase();
  return [m.hostname, m.label, osLabel(m.osId, m.osVersion), m.ip].some((v) =>
    v?.toLowerCase().includes(needle),
  );
}

// Filters are ANDed; input order is preserved (sorting is the query's job).
export function filterMachines(rows: MachineRow[], f: MachineFilters): MachineRow[] {
  return rows.filter(
    (m) =>
      (f.archived || m.archivedAt === null) &&
      (f.q === null || matchesQuery(m, f.q)) &&
      (f.status === null || machineStatus(m.agents) === f.status) &&
      (f.os === null || m.osId === f.os) &&
      (!f.critical || hasCritical(m)) &&
      (!f.kev || hasKev(m)),
  );
}

export function summarizeMachines(rows: MachineRow[]): {
  machines: number;
  withCritical: number;
  archived: number;
} {
  const active = rows.filter((m) => m.archivedAt === null);
  return {
    machines: active.length,
    withCritical: active.filter(hasCritical).length,
    archived: rows.length - active.length,
  };
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

// The line under the page title: "12 machines · 3 with critical vulnerabilities".
export function machinesSummaryText(s: { machines: number; withCritical: number }): string {
  const base = plural(s.machines, "machine", "machines");
  return s.withCritical > 0 ? `${base} · ${s.withCritical} with critical vulnerabilities` : base;
}

// Tooltip for a row's "+N in images". `images` counts the running images
// with at least one open finding, so it is only ever shown next to N.
export function imageVulnsTitle(i: MachineRow["images"]): string {
  const base = `${plural(i.vulns, "vulnerability", "vulnerabilities")} in ${plural(i.images, "running image", "running images")} · ${i.critical} critical`;
  return i.kev > 0 ? `${base} · ${i.kev} known exploited` : base;
}

// The pills show critical / high / medium only; a machine whose open host
// package vulnerabilities are all low gets a muted "N low" instead of
// "0 0 0". Null when the pills already say something.
export function lowOnlyCount(v: SeverityCounts): number | null {
  return v.critical === 0 && v.high === 0 && v.medium === 0 && v.low > 0 ? v.low : null;
}
