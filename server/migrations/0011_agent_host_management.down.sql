BEGIN;

DROP FUNCTION mgmt_detach_host(uuid, uuid, uuid);
DROP FUNCTION mgmt_merge_host(uuid, uuid, uuid);
DROP FUNCTION mgmt_dismiss_duplicate(uuid, uuid);
DROP FUNCTION mgmt_delete_host(uuid, uuid, text);
DROP FUNCTION mgmt_set_host_archived(uuid, uuid, boolean);
DROP FUNCTION mgmt_rename_host(uuid, uuid, text);
DROP FUNCTION mgmt_request_rotation(uuid, uuid);
DROP FUNCTION mgmt_revoke_agent(uuid, uuid);
DROP FUNCTION mgmt_agent_active(timestamptz, timestamptz, int);

DROP INDEX enrollment_tokens_expires_at_idx;

ALTER TABLE hosts
    DROP CONSTRAINT hosts_merged_archived_ck,
    DROP COLUMN duplicate_dismissed_of,
    DROP COLUMN merged_into,
    DROP COLUMN archived_at;

ALTER TABLE agent_credentials
    DROP CONSTRAINT agent_credentials_previous_ck,
    DROP COLUMN rotate_requested_at,
    DROP COLUMN previous_expires_at,
    DROP COLUMN previous_secret_hash;

COMMIT;
