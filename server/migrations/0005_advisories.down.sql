-- Restores the 0001 `vulnerabilities` table (empty) and
-- findings.vulnerability_id. Synced advisory data and any matches are
-- dropped; a re-up re-imports them on the next sync.

BEGIN;

DROP TABLE IF EXISTS software_vulnerabilities;
DROP TABLE IF EXISTS feed_sync_state;
DROP TABLE IF EXISTS cves;
DROP TABLE IF EXISTS advisory_changes;
DROP TABLE IF EXISTS advisory_affected;
DROP TABLE IF EXISTS advisories;
DROP TABLE IF EXISTS distro_releases;

CREATE TABLE vulnerabilities (
    id                  text PRIMARY KEY,
    ecosystem           text NOT NULL,
    package_name        text NOT NULL,
    fixed_version       text,
    distro_release      text NOT NULL,
    summary             text,
    cvss_score          numeric,
    epss_score          numeric,
    epss_percentile     numeric,
    is_kev              boolean NOT NULL DEFAULT false,
    kev_added_at        date,
    source_updated_at   timestamptz,
    synced_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX vulnerabilities_package_release_idx ON vulnerabilities(package_name, distro_release);

DROP INDEX IF EXISTS findings_vuln_key_idx;
ALTER TABLE findings DROP COLUMN vuln_key;
ALTER TABLE findings ADD COLUMN vulnerability_id text REFERENCES vulnerabilities(id);

COMMIT;
