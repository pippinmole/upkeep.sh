BEGIN;

ALTER TABLE alert_rules
    DROP CONSTRAINT alert_rules_finding_kinds_ck,
    DROP COLUMN finding_kinds;
DROP FUNCTION image_scores(uuid);
DROP TABLE image_sbom_scores;
DELETE FROM findings WHERE kind = 'vulnerable_image';
DROP INDEX findings_image_open_idx;
ALTER TABLE findings
    DROP CONSTRAINT findings_image_key_ck,
    DROP COLUMN image_id,
    DROP COLUMN image_os,
    DROP COLUMN image_arch,
    DROP COLUMN image_variant,
    DROP COLUMN image_refs,
    DROP COLUMN container_names;

COMMIT;
