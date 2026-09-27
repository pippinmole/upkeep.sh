"use server";

import { revalidatePath } from "next/cache";

import { auth } from "@/lib/auth";
import { pool } from "@/lib/db";
import { isUuid } from "@/lib/queries-inventory";
import { getRemoteTarget, type RemoteTarget } from "@/lib/queries-remote";

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
  | "mgmt_detach_host"
  | "mgmt_confirm_host_key"
  | "mgmt_remove_remote_target";

const MESSAGES: Record<string, string> = {
  not_found: "Not found. It may have been deleted or changed; reload the page.",
  revoked: "This agent is revoked.",
  merged: "A merged host stays archived.",
  confirmation_mismatch: "The name you typed doesn't match the hostname.",
  not_flagged: "This host is no longer flagged as a duplicate of that host.",
  archived: "Unarchive both hosts before merging.",
  agent_active: "The agent is still active. Revoke it first, or wait until it stops reporting.",
  host_key_changed:
    "The host presented a different key in the meantime. Check the new fingerprint.",
  agent_no_ssh: "This agent can't reach other hosts yet. Upgrade it to the latest version.",
  invalid_address: "Enter a hostname or an IP address, without a user or port.",
  invalid_port: "The port must be between 1 and 65535.",
  invalid_username: "Use a Linux username: lowercase letters, digits, _ . and -.",
  duplicate_target: "This agent already collects that address and port.",
};

const fail = (error: string) => ({ ok: false, error }) as const;

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

// Remote (ssh) hosts, migration 0012.

export type AddRemoteHostResult = { ok: true; hostId: string } | { ok: false; error: string };

export async function addRemoteHost(input: {
  agentId: string;
  address: string;
  port: number;
  username: string;
  label: string;
}): Promise<AddRemoteHostResult> {
  const { agentId, address, port, username, label } = input ?? {};
  if (
    !ids(agentId) ||
    typeof address !== "string" ||
    address.length > 253 ||
    !Number.isInteger(port) ||
    typeof username !== "string" ||
    username.length > 32 ||
    typeof label !== "string" ||
    label.length > 100
  ) {
    return bad;
  }
  const session = await auth();
  if (!session?.user?.id) return fail("You are not signed in.");
  let status: string | undefined;
  try {
    const { rows } = await pool.query<{ status: string }>(
      `SELECT mgmt_add_remote_host($1, $2, $3, $4, $5, $6) AS status`,
      [session.user.id, agentId, address, port, username, label],
    );
    status = rows[0]?.status;
  } catch (err) {
    console.error("mgmt_add_remote_host:", err);
    return fail("Something went wrong. Please try again.");
  }
  const hostId = status?.startsWith("ok:") ? status.slice(3) : null;
  if (!hostId) return fail(MESSAGES[status ?? ""] ?? "Something went wrong.");
  revalidatePath("/dashboard", "layout");
  return { ok: true, hostId };
}

// key is the pending key the user was shown; the function refuses if the
// host has presented a different one since.
export async function confirmHostKey(
  agentId: string,
  hostId: string,
  key: string,
): Promise<ActionResult> {
  if (!ids(agentId, hostId) || typeof key !== "string" || key.length > 4096) return bad;
  return call("mgmt_confirm_host_key", [agentId, hostId, key]);
}

export async function removeRemoteTarget(agentId: string, hostId: string): Promise<ActionResult> {
  if (!ids(agentId, hostId)) return bad;
  return call("mgmt_remove_remote_target", [agentId, hostId]);
}

// Polled by the setup dialog while it's open.
export async function fetchRemoteTarget(
  agentId: string,
  hostId: string,
): Promise<RemoteTarget | null> {
  if (!ids(agentId, hostId)) return null;
  const session = await auth();
  if (!session?.user?.id) return null;
  return getRemoteTarget(session.user.id, agentId, hostId);
}
