-- Reverts the agent/host split to agent == host. Only credentials whose
-- agent id is also a host id (backfilled agents, or agents whose local host
-- happens to reuse that id) can be kept; agents enrolled after 0008 lose
-- their credential and must re-enroll.

BEGIN;

DROP INDEX IF EXISTS snapshots_agent_id_idx;
ALTER TABLE snapshots
    DROP COLUMN agent_id,
    DROP COLUMN uptime_seconds,
    DROP COLUMN facts;

DROP TABLE agent_hosts;
DROP TABLE host_identities;

ALTER TABLE hosts
    DROP COLUMN os_family,
    DROP COLUMN os_id,
    DROP COLUMN os_version,
    DROP COLUMN os_codename,
    DROP COLUMN os_build,
    DROP COLUMN kernel,
    DROP COLUMN arch,
    DROP COLUMN duplicate_of;

ALTER TABLE enrollment_tokens DROP COLUMN agent_name;

ALTER TABLE agent_credentials DROP CONSTRAINT agent_credentials_agent_id_fkey;
DELETE FROM agent_credentials c WHERE NOT EXISTS (SELECT 1 FROM hosts h WHERE h.id = c.agent_id);
ALTER TABLE agent_credentials RENAME COLUMN agent_id TO host_id;
ALTER TABLE agent_credentials
    ADD CONSTRAINT agent_credentials_host_id_fkey
        FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE;

DROP TABLE agents;

COMMIT;
