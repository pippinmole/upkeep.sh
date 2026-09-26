-- Recreates snapshot_packages exactly as in 0001, empty. The dropped rows
-- are not restored; host_software keeps the history they fed.

BEGIN;

CREATE TABLE snapshot_packages (
    snapshot_id   uuid NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    name          text NOT NULL,
    version       text NOT NULL,
    arch          text NOT NULL,
    PRIMARY KEY (snapshot_id, name, arch)
);

COMMIT;
