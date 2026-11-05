// Types and pure helpers for the Machines home page.

export type AgentStatus = "online" | "stale" | "never" | "revoked";
export type MachineAgent = { id: string; name: string; mode: "local" | "ssh" | "winrm"; status: AgentStatus };
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
