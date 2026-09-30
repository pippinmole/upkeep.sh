DROP INDEX IF EXISTS findings_vuln_key_trgm_idx;
DROP INDEX IF EXISTS software_versions_name_trgm_idx;
-- Nothing else in the schema uses pg_trgm.
DROP EXTENSION IF EXISTS pg_trgm;
