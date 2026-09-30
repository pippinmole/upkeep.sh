-- P1.5 agent/host split (DOMAIN_MODEL.md §4.3, §4.6, §4.7).
--
-- Before: agent == host. Enrollment created a hosts row, the agent_id it
-- returned WAS hosts.id, and agent_credentials was keyed by host_id.
-- After: an agent (one deployed collector with its own credential) collects
-- one or more hosts through agent_hosts assignments. Enrollment creates an
-- agent; the host is created or re-attached on the agent's first push, by
-- identity (host_identities). Everything that hangs off a host (snapshots,
-- host_software, findings, ...) keeps keying on host_id, unchanged.
--
-- Backfill reuses ids: every existing host gets an agent with the SAME id,
-- so every deployed agent's credentials.json agent_id stays valid and its
-- pushes resolve (through its backfilled local assignment) to its old host.

BEGIN;

CREATE TABLE agents (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id               uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                  text NOT NULL,        -- enrollment_tokens.agent_name, else the enrolling hostname
    agent_version         text,                 -- payload agent.version / enroll version; NULL for older agents
    platform              text,                 -- 'linux/amd64', ...; NULL for older agents
    push_interval_seconds int,                  -- payload agent.interval_seconds; NULL = unknown (assume 15m)
    created_at            timestamptz NOT NULL DEFAULT now(),
    last_seen_at          timestamptz,          -- last authenticated push
    revoked_at            timestamptz           -- set: credential refused, agent no longer "active"
);
CREATE INDEX agents_user_id_idx ON agents (user_id);

INSERT INTO agents (id, user_id, name, created_at, last_seen_at)
SELECT h.id, h.user_id, h.hostname, h.created_at, h.last_seen_at FROM hosts h;

-- Re-key agent_credentials host_id -> agent_id (same values, see above).
ALTER TABLE agent_credentials DROP CONSTRAINT agent_credentials_host_id_fkey;
ALTER TABLE agent_credentials RENAME COLUMN host_id TO agent_id;
ALTER TABLE agent_credentials
    ADD CONSTRAINT agent_credentials_agent_id_fkey
        FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE;

-- Optional pre-set agent name from the dashboard's "Register agent" dialog.
ALTER TABLE enrollment_tokens ADD COLUMN agent_name text;

-- Current OS summary, maintained by ingest from the host's newest snapshot
-- (by collected_at), so host lists never need a LATERAL join for it.
-- snapshots keeps its os_* columns as the per-push record.
--   duplicate_of: set when this host was created for an agent whose host
--   identity (machine-id) already belongs to host `duplicate_of` with a
--   different, still-active local agent (cloned VM, or two agents on one
--   machine): "possible duplicate identity" (Q12). Never auto-merged.
ALTER TABLE hosts
    ADD COLUMN os_family    text CHECK (os_family IN ('linux', 'windows', 'macos')),
    ADD COLUMN os_id        text,
    ADD COLUMN os_version   text,
    ADD COLUMN os_codename  text,
    ADD COLUMN os_build     text,
    ADD COLUMN kernel       text,
    ADD COLUMN arch         text,
    ADD COLUMN duplicate_of uuid REFERENCES hosts(id) ON DELETE SET NULL;

-- Stable machine identifiers, unique per user. kind is the payload's
-- host.identity key: 'machine_id' (Linux /etc/machine-id); later
-- 'machine_guid' / 'smbios_uuid' (Windows), 'platform_uuid' (macOS).
-- A host may have several (e.g. its machine-id was regenerated).
CREATE TABLE host_identities (
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind        text NOT NULL,
    value       text NOT NULL,
    host_id     uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, kind, value)
);
CREATE INDEX host_identities_host_id_idx ON host_identities (host_id);

-- "This agent collects this host, in this mode." Only 'local' is
-- implemented; ssh/winrm are reserved (Q3-Q5). target_ref is what the agent
-- sends as host.ref ('local' for its own machine).
CREATE TABLE agent_hosts (
    agent_id          uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    host_id           uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    mode              text NOT NULL CHECK (mode IN ('local', 'ssh', 'winrm')),
    target_ref        text NOT NULL DEFAULT 'local',
    address           text,                     -- remote modes only
    enabled           boolean NOT NULL DEFAULT true,
    created_at        timestamptz NOT NULL DEFAULT now(),
    last_collected_at timestamptz,              -- received time of the last snapshot via this assignment
    last_error        text,
    PRIMARY KEY (agent_id, host_id),
    UNIQUE (agent_id, target_ref),
    CHECK ((mode = 'local') = (target_ref = 'local'))
);
CREATE UNIQUE INDEX agent_hosts_one_local_idx ON agent_hosts (agent_id) WHERE mode = 'local';
CREATE INDEX agent_hosts_host_id_idx ON agent_hosts (host_id);

INSERT INTO agent_hosts (agent_id, host_id, mode, target_ref, created_at, last_collected_at)
SELECT h.id, h.id, 'local', 'local', h.created_at,
       (SELECT max(s.received_at) FROM snapshots s WHERE s.host_id = h.id)
FROM hosts h;

-- Which agent collected each snapshot (NULL once that agent is deleted).
-- uptime_seconds / facts are reserved for the Linux breadth collectors.
ALTER TABLE snapshots
    ADD COLUMN agent_id       uuid REFERENCES agents(id) ON DELETE SET NULL,
    ADD COLUMN uptime_seconds bigint,
    ADD COLUMN facts          jsonb NOT NULL DEFAULT '{}';
UPDATE snapshots SET agent_id = host_id;
CREATE INDEX snapshots_agent_id_idx ON snapshots (agent_id);

-- OS summary backfill from each host's newest snapshot. Every agent that
-- existed before this migration was the Linux agent.
UPDATE hosts h
SET os_family   = 'linux',
    os_id       = NULLIF(s.os_id, ''),
    os_version  = NULLIF(s.os_version_id, ''),
    os_codename = NULLIF(s.os_codename, ''),
    kernel      = s.kernel_release
FROM (
    SELECT DISTINCT ON (host_id) host_id, os_id, os_version_id, os_codename, kernel_release
    FROM snapshots
    ORDER BY host_id, collected_at DESC, received_at DESC
) s
WHERE s.host_id = h.id;

COMMIT;
