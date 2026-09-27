"use server";

import { revalidatePath } from "next/cache";

import { auth } from "@/lib/auth";
import { pool } from "@/lib/db";
import { isUuid } from "@/lib/queries-inventory";

// Agent and host management (DOMAIN_MODEL.md §4.3 "Management"). Every
// mutation is one call to a mgmt_* SQL function (migrations/0011), which
// scopes every row it touches by the signed-in user's id; the Go
// integration tests call the same functions, cross-tenant cases included.
// Arguments are bound parameters; the function name is from the fixed
// union below, never from input.

export type ActionResult = { ok: true } | { ok: false; error: string };

type MgmtFn =
  | "mgmt_revoke_agent"
  | "mgmt_request_rotation"
  | "mgmt_rename_host"
  | "mgmt_set_host_archived"
  | "mgmt_delete_host"
  | "mgmt_dismiss_duplicate"
  | "mgmt_merge_host"
  | "mgmt_detach_host";

const MESSAGES: Record<string, string> = {
  not_found: "Not found. It may have been deleted or changed; reload the page.",
  revoked: "This agent is revoked.",
  merged: "A merged host stays archived.",
  confirmation_mismatch: "The name you typed doesn't match the hostname.",
  not_flagged: "This host is no longer flagged as a duplicate of that host.",
  archived: "Unarchive both hosts before merging.",
  agent_active: "The agent is still active. Revoke it first, or wait until it stops reporting.",
};

const fail = (error: string): ActionResult => ({ ok: false, error });

async function call(fn: MgmtFn, args: unknown[]): Promise<ActionResult> {
  const session = await auth();
  if (!session?.user?.id) return fail("You are not signed in.");
  const params = args.map((_, i) => `$${i + 2}`).join(", ");
  try {
    const { rows } = await pool.query<{ status: string }>(`SELECT ${fn}($1, ${params}) AS status`, [
      session.user.id,
      ...args,
    ]);
    const status = rows[0]?.status;
    if (status !== "ok") return fail(MESSAGES[status ?? ""] ?? "Something went wrong.");
  } catch (err) {
    console.error(`${fn}:`, err);
    return fail("Something went wrong. Please try again.");
  }
  revalidatePath("/dashboard", "layout");
  return { ok: true };
}

const bad = fail("Invalid request.");
const ids = (...v: unknown[]) => v.every((x) => typeof x === "string" && isUuid(x));

export async function revokeAgent(agentId: string): Promise<ActionResult> {
  if (!ids(agentId)) return bad;
  return call("mgmt_revoke_agent", [agentId]);
}

export async function requestAgentRotation(agentId: string): Promise<ActionResult> {
  if (!ids(agentId)) return bad;
  return call("mgmt_request_rotation", [agentId]);
}

export async function renameHost(hostId: string, label: string): Promise<ActionResult> {
  if (!ids(hostId) || typeof label !== "string" || label.length > 100) return bad;
  return call("mgmt_rename_host", [hostId, label]);
}

export async function setHostArchived(hostId: string, archived: boolean): Promise<ActionResult> {
  if (!ids(hostId) || typeof archived !== "boolean") return bad;
  return call("mgmt_set_host_archived", [hostId, archived]);
}

export async function deleteHost(hostId: string, confirmHostname: string): Promise<ActionResult> {
  if (!ids(hostId) || typeof confirmHostname !== "string") return bad;
  return call("mgmt_delete_host", [hostId, confirmHostname]);
}

export async function dismissDuplicate(hostId: string): Promise<ActionResult> {
  if (!ids(hostId)) return bad;
  return call("mgmt_dismiss_duplicate", [hostId]);
}

export async function mergeHost(duplicateId: string, originalId: string): Promise<ActionResult> {
  if (!ids(duplicateId, originalId)) return bad;
  return call("mgmt_merge_host", [duplicateId, originalId]);
}

export async function detachHost(agentId: string, hostId: string): Promise<ActionResult> {
  if (!ids(agentId, hostId)) return bad;
  return call("mgmt_detach_host", [agentId, hostId]);
}
