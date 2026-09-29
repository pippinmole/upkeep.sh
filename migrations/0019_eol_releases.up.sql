-- P2a end-of-life base images (docs/tasks/phase-2a-image-vulns.md
-- "End-of-life base images"; DOMAIN_MODEL.md §2.3, §2.6): past releases
-- of the assessed distros, listed unsupported. No schema change.
--
-- Advisories are imported only for supported releases, and
-- matcher.Assessed (matcher.Version 3) now requires one, so packages of a
-- release that is out of support, or not listed here at all, count as
-- "not assessed" and their image is never shown clean. Listing the common
-- end-of-life releases lets the dashboard say "Debian 10 (buster), out of
-- support since 2024-06-30" instead of "release not recognised", and lets
-- purl.ReleaseFor map their VERSION_ID to a codename. They are never
-- imported unless `supported` is flipped.
--
-- EOL dates are the end of security support, approximate, as in 0005 and
-- 0016: Debian including LTS (https://wiki.debian.org/LTS), Ubuntu
-- standard support excluding ESM (https://ubuntu.com/about/release-cycle),
-- Alpine per https://alpinelinux.org/releases.json (checked 2026-09-29).

BEGIN;

INSERT INTO distro_releases (distro, codename, version, osv_ecosystem, eol_date, supported) VALUES
    ('debian', 'jessie',   '8',     'Debian:8',         '2020-06-30', false),
    ('debian', 'stretch',  '9',     'Debian:9',         '2022-06-30', false),
    ('debian', 'buster',   '10',    'Debian:10',        '2024-06-30', false),
    ('ubuntu', 'trusty',   '14.04', 'Ubuntu:14.04:LTS', '2019-04-30', false),
    ('ubuntu', 'xenial',   '16.04', 'Ubuntu:16.04:LTS', '2021-04-30', false),
    ('ubuntu', 'bionic',   '18.04', 'Ubuntu:18.04:LTS', '2023-05-31', false),
    ('ubuntu', 'kinetic',  '22.10', 'Ubuntu:22.10',     '2023-07-20', false),
    ('ubuntu', 'lunar',    '23.04', 'Ubuntu:23.04',     '2024-01-25', false),
    ('ubuntu', 'mantic',   '23.10', 'Ubuntu:23.10',     '2024-07-11', false),
    ('ubuntu', 'oracular', '24.10', 'Ubuntu:24.10',     '2025-07-10', false),
    ('ubuntu', 'plucky',   '25.04', 'Ubuntu:25.04',     '2026-01-15', false),
    ('alpine', '3.14',     '3.14',  'Alpine:v3.14',     '2023-05-01', false),
    ('alpine', '3.15',     '3.15',  'Alpine:v3.15',     '2023-11-01', false),
    ('alpine', '3.16',     '3.16',  'Alpine:v3.16',     '2024-05-23', false),
    ('alpine', '3.17',     '3.17',  'Alpine:v3.17',     '2024-11-22', false),
    ('alpine', '3.18',     '3.18',  'Alpine:v3.18',     '2025-05-09', false)
ON CONFLICT (distro, codename) DO NOTHING;

COMMIT;
