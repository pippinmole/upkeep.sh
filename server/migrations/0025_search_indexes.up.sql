-- Trigram indexes for the dashboard's global search (web/src/lib/search).
--
-- Search matches substrings (ILIKE '%q%'), which a btree can't serve. Two
-- tables grow with the install rather than with what a person scrolls
-- through, so a sequential scan per keystroke would get slow:
--
--   software_versions  every interned package version, from hosts and
--                      from image package lists; the package search
--                      filters it by name before joining the workspace's
--                      host_software.
--   findings           every finding ever opened, resolved ones included;
--                      the vulnerability search filters it by vuln_key.
--
-- The CVE feed tables (cves, advisories) need nothing new: search only
-- reads them by exact id (primary keys, advisories_vuln_key_idx and the
-- GIN advisories_cve_ids_idx). Hosts, agents, images and containers are
-- small per workspace and are scanned from the workspace's hosts.
--
-- pg_trgm is a trusted extension (PostgreSQL 13+), so the database owner
-- can create it without superuser. Queries under 3 characters can't use a
-- trigram index and fall back to a scan, which is fine at that length.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX software_versions_name_trgm_idx
    ON software_versions USING gin (name gin_trgm_ops);

CREATE INDEX findings_vuln_key_trgm_idx
    ON findings USING gin (vuln_key gin_trgm_ops)
    WHERE vuln_key IS NOT NULL;
