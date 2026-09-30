-- Retire snapshot_packages (DOMAIN_MODEL.md §6 Q6). host_software /
-- software_versions (0003) are the inventory of record, and 0003's
-- backfill was the last reader of this table. Nothing writes it any more.

BEGIN;

DROP TABLE IF EXISTS snapshot_packages;

COMMIT;
