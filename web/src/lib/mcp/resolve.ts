import * as z from "zod";

import { pool } from "@/lib/db";
import { isUuid } from "@/lib/queries-inventory";

import { ToolError, type ToolContext } from "./tool";

// Hosts are addressed by id or hostname (docs/MCP.md#tools). A hostname
// several hosts share is an error listing the candidates, never a guess.
// Archived hosts aren't addressable, as on the dashboard's lists.

export type ResolvedHost = { id: string; hostname: string; label: string | null };

export type HostLookup = (workspaceId: string, ref: string) => Promise<ResolvedHost[]>;

const CANDIDATES_LISTED = 10;

const lookupHosts: HostLookup = async (workspaceId, ref) => {
  const { rows } = await pool.query<ResolvedHost>(
    isUuid(ref)
      ? `SELECT id, hostname, label FROM hosts
         WHERE workspace_id = $1 AND archived_at IS NULL AND id = $2::uuid`
      : `SELECT id, hostname, label FROM hosts
         WHERE workspace_id = $1 AND archived_at IS NULL AND lower(hostname) = lower($2)
         ORDER BY hostname, id
         LIMIT ${CANDIDATES_LISTED + 1}`,
    [workspaceId, ref],
  );
  return rows;
};

export async function resolveHost(
  workspaceId: string,
  ref: string,
  lookup: HostLookup = lookupHosts,
): Promise<ResolvedHost> {
  const hosts = await lookup(workspaceId, ref);
  if (hosts.length === 1) return hosts[0];
  if (hosts.length === 0) {
    throw new ToolError(
      `No host with the id or hostname ${JSON.stringify(ref)} in this workspace. Check the ` +
        "hostname, or pass the host's id.",
    );
  }
  const shown = hosts
    .slice(0, CANDIDATES_LISTED)
    .map((h) => `${h.hostname}${h.label ? ` (${h.label})` : ""}: ${h.id}`);
  const more = hosts.length > CANDIDATES_LISTED ? "; and more" : "";
  throw new ToolError(
    `Several hosts are named ${JSON.stringify(ref)}; pass one of their ids instead: ` +
      `${shown.join("; ")}${more}.`,
  );
}

// The host a host tool answered for, as every host tool returns it.
export const hostRef = z.object({
  id: z.string(),
  hostname: z.string(),
  label: z.string().nullable(),
  dashboard_url: z.string(),
});

export function hostRefOf(
  host: { id: string; hostname: string; label: string | null },
  ctx: ToolContext,
): z.input<typeof hostRef> {
  return {
    id: host.id,
    hostname: host.hostname,
    label: host.label,
    dashboard_url: ctx.dashboardUrl(`/dashboard/hosts/${host.id}`),
  };
}

// "web-01 (eu)" for the text renderings.
export function hostName(host: { hostname: string; label: string | null }): string {
  return host.label ? `${host.hostname} (${host.label})` : host.hostname;
}
