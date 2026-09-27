BEGIN;

ALTER TABLE snapshots DROP COLUMN arch;
DROP TABLE host_users;
DROP TABLE host_listeners;
DROP TABLE host_services;
DROP TABLE host_fact_state;

COMMIT;
