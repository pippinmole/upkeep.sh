BEGIN;

DROP TABLE IF EXISTS host_inventory_state;
DROP TABLE IF EXISTS host_software;
DROP TABLE IF EXISTS software_versions;

ALTER TABLE snapshots
    DROP COLUMN IF EXISTS collector_status,
    DROP COLUMN IF EXISTS package_set_hashes;

DROP INDEX IF EXISTS hosts_user_id_idx;

COMMIT;
