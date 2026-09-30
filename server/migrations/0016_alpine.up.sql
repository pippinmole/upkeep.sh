-- P2a Alpine (DOMAIN_MODEL.md §2.3, §2.5; docs/tasks/phase-2a-image-vulns.md "Alpine"):
-- Alpine releases for the OSV `Alpine` sync and the apk matcher. No
-- schema change: advisory_affected / software_versions already carry
-- distro 'alpine' and release as text.
--
-- Alpine has no codenames. Its advisories (secdb, OSV "Alpine:v3.22")
-- are per branch, and image packages are interned under the branch
-- (purl.ReleaseFor: major.minor of VERSION_ID, "3.22.1" -> "3.22"), so
-- the branch is both `codename` (the release key everything joins on)
-- and `version`.
--
-- EOL dates are the end of security support per
-- https://alpinelinux.org/releases.json (checked 2026-09-28). 3.19 and
-- 3.20 are past it and listed unsupported, like Debian 11, so flipping
-- `supported` is all it takes to import them.

BEGIN;

INSERT INTO distro_releases (distro, codename, version, osv_ecosystem, eol_date, supported) VALUES
    ('alpine', '3.19', '3.19', 'Alpine:v3.19', '2025-11-01', false),
    ('alpine', '3.20', '3.20', 'Alpine:v3.20', '2026-04-01', false),
    ('alpine', '3.21', '3.21', 'Alpine:v3.21', '2026-11-01', true),
    ('alpine', '3.22', '3.22', 'Alpine:v3.22', '2027-05-01', true),
    ('alpine', '3.23', '3.23', 'Alpine:v3.23', '2027-11-01', true),
    ('alpine', '3.24', '3.24', 'Alpine:v3.24', '2028-06-01', true);

COMMIT;
