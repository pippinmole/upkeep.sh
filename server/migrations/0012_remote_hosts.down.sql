BEGIN;

DROP FUNCTION mgmt_remove_remote_target(uuid, uuid, uuid);
DROP FUNCTION mgmt_confirm_host_key(uuid, uuid, uuid, text);
DROP FUNCTION mgmt_add_remote_host(uuid, uuid, text, int, text, text);

-- Remote assignments can't exist without the columns that describe them.
DELETE FROM agent_hosts WHERE mode <> 'local';

ALTER TABLE agent_hosts
    DROP CONSTRAINT agent_hosts_remote_ck,
    DROP COLUMN last_error_code,
    DROP COLUMN last_attempt_at,
    DROP COLUMN host_key_pending,
    DROP COLUMN host_key,
    DROP COLUMN username,
    DROP COLUMN port;

ALTER TABLE agents DROP COLUMN ssh_public_key;

COMMIT;
