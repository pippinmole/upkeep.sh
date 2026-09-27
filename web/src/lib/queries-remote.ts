import { createHash } from "crypto";

import { pool } from "@/lib/db";
import { AGENT_STATUS_SQL, type AgentStatus } from "@/lib/queries";

// Remote (ssh) hosts: agents that can collect them, and one assignment's
// setup/connection state (migration 0012, DOMAIN_MODEL.md §4.2).

// OpenSSH's SHA256 fingerprint of a "type base64" key: what
// `ssh-keygen -lf` prints, so the user can compare it on the host.
export function sshFingerprint(key: string | null): string | null {
  const b64 = key?.split(/\s+/)[1];
  if (!b64) return null;
  const digest = createHash("sha256").update(Buffer.from(b64, "base64")).digest("base64");
  return `SHA256:${digest.replace(/=+$/, "")}`;
}

export type RemoteCollectorAgent = {
  id: string;
  name: string;
  status: AgentStatus;
  // The agent reported an SSH public key, which only builds with remote
  // collection support do (they generate the key on start). Older agents
  // never fetch a target list, so a host added to them would never be
  // collected.
  supportsRemote: boolean;
};

// The user's agents that aren't revoked, for "Reach it from an existing
// agent": remote-capable ones first.
export async function getRemoteCollectorAgents(userId: string): Promise<RemoteCollectorAgent[]> {
  const { rows } = await pool.query<RemoteCollectorAgent>(
    `SELECT a.id, a.name, ${AGENT_STATUS_SQL} AS status,
            a.ssh_public_key IS NOT NULL AS "supportsRemote"
     FROM agents a
     WHERE a.user_id = $1 AND a.revoked_at IS NULL
     ORDER BY a.ssh_public_key IS NULL, a.last_seen_at DESC NULLS LAST, a.name`,
    [userId],
  );
  return rows;
}

export type RemoteTargetErrorCode =
  | "host_key_unconfirmed"
  | "host_key_mismatch"
  | "auth_failed"
  | "unreachable"
  | "sftp_failed"
  | "push_failed";

export type RemoteTarget = {
  agentId: string;
  agentName: string;
  agentStatus: AgentStatus;
  agentPublicKey: string | null;
  hostId: string;
  hostname: string;
  label: string | null;
  address: string;
  port: number;
  username: string;
  hostKey: string | null;
  hostKeyFingerprint: string | null;
  // A presented key waiting for confirmation (first contact or changed).
  pendingKey: string | null;
  pendingKeyType: string | null;
  pendingFingerprint: string | null;
  lastAttemptAt: string | null;
  lastCollectedAt: string | null;
  errorCode: RemoteTargetErrorCode | null;
  error: string | null;
};

type Row = {
  agent_id: string;
  agent_name: string;
  agent_status: AgentStatus;
  ssh_public_key: string | null;
  host_id: string;
  hostname: string;
  label: string | null;
  address: string;
  port: number;
  username: string;
  host_key: string | null;
  host_key_pending: string | null;
  last_attempt_at: Date | null;
  last_collected_at: Date | null;
  last_error_code: RemoteTargetErrorCode | null;
  last_error: string | null;
};

// One remote assignment of the user's, or null. Scoped by both the
// agent's and the host's user_id.
export async function getRemoteTarget(
  userId: string,
  agentId: string,
  hostId: string,
): Promise<RemoteTarget | null> {
  const { rows } = await pool.query<Row>(
    `SELECT a.id AS agent_id, a.name AS agent_name, ${AGENT_STATUS_SQL} AS agent_status,
            a.ssh_public_key, h.id AS host_id, h.hostname, h.label,
            ah.address, ah.port, ah.username, ah.host_key, ah.host_key_pending,
            ah.last_attempt_at, ah.last_collected_at, ah.last_error_code, ah.last_error
     FROM agent_hosts ah
     JOIN agents a ON a.id = ah.agent_id AND a.user_id = $1
     JOIN hosts h ON h.id = ah.host_id AND h.user_id = $1
     WHERE ah.agent_id = $2 AND ah.host_id = $3 AND ah.mode <> 'local'`,
    [userId, agentId, hostId],
  );
  const r = rows[0];
  if (!r) return null;
  return {
    agentId: r.agent_id,
    agentName: r.agent_name,
    agentStatus: r.agent_status,
    agentPublicKey: r.ssh_public_key,
    hostId: r.host_id,
    hostname: r.hostname,
    label: r.label,
    address: r.address,
    port: r.port,
    username: r.username,
    hostKey: r.host_key,
    hostKeyFingerprint: sshFingerprint(r.host_key),
    pendingKey: r.host_key_pending,
    pendingKeyType: r.host_key_pending?.split(" ")[0] ?? null,
    pendingFingerprint: sshFingerprint(r.host_key_pending),
    lastAttemptAt: r.last_attempt_at?.toISOString() ?? null,
    lastCollectedAt: r.last_collected_at?.toISOString() ?? null,
    errorCode: r.last_error_code,
    error: r.last_error,
  };
}
