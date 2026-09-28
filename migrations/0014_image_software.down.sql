BEGIN;

DROP FUNCTION image_sbom_effective(uuid);
DROP TABLE image_software;
DROP TABLE image_sbom_state;

COMMIT;
