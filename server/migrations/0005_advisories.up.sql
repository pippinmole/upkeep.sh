-- P1b data side: normalized advisory store (DOMAIN_MODEL.md §2.3, §2.4,
-- §2.6). Replaces the single-row-per-CVE `vulnerabilities` table, whose
-- primary key could only hold one package/release per CVE.
--
-- Written by the Go worker (server/cmd/worker): OSV Debian/Ubuntu sync
-- fills advisories/advisory_affected/advisory_changes; CISA KEV + FIRST
-- EPSS (and CVSS from OSV) fill cves. software_vulnerabilities is created
-- empty here; the matcher fills it.
--
-- Nothing is deployed yet, so `vulnerabilities` is dropped rather than
-- migrated (it was never written).

BEGIN;

-- findings referenced vulnerabilities(id); matches and findings are keyed
-- by vuln_key (a CVE id, or an advisory id when there is no CVE), which is
-- not always a cves row, so this is plain text with no FK (§2.6).
ALTER TABLE findings DROP COLUMN vulnerability_id;
ALTER TABLE findings ADD COLUMN vuln_key text;
CREATE INDEX findings_vuln_key_idx ON findings (vuln_key) WHERE vuln_key IS NOT NULL;

DROP TABLE vulnerabilities;

-- Which distro releases we understand and import advisories for. The
-- advisory sync imports only rows whose release is supported = true, so
-- enabling a release is a data change (then run a full OSV sync).
-- Matched by (distro, version) against the OSV ecosystem string, so
-- 'Ubuntu:22.04:LTS' and 'Ubuntu:Pro:22.04:LTS' (ESM) both land on jammy.
CREATE TABLE distro_releases (
    distro        text NOT NULL,             -- os.id: 'debian' | 'ubuntu'
    codename      text NOT NULL,             -- os.codename: 'bookworm', 'jammy'
    version       text NOT NULL,             -- '12', '22.04'
    osv_ecosystem text NOT NULL,             -- canonical OSV name for the standard archive
    eol_date      date,                      -- end of security support (Debian: incl. LTS; Ubuntu: standard, excl. ESM); approximate
    supported     boolean NOT NULL DEFAULT true,
    PRIMARY KEY (distro, codename),
    UNIQUE (distro, version)
);

-- As of 2026-09. Debian 11 left LTS on 2026-08-31; Debian 14 (forky) is
-- testing; Ubuntu 20.04 is ESM-only; 25.10 reached EOL in 2026-07. They
-- are listed so flipping `supported` is all it takes to import them.
INSERT INTO distro_releases (distro, codename, version, osv_ecosystem, eol_date, supported) VALUES
    ('debian', 'bullseye', '11',    'Debian:11',        '2026-08-31', false),
    ('debian', 'bookworm', '12',    'Debian:12',        '2028-06-30', true),
    ('debian', 'trixie',   '13',    'Debian:13',        '2030-06-30', true),
    ('debian', 'forky',    '14',    'Debian:14',        NULL,         false),
    ('ubuntu', 'focal',    '20.04', 'Ubuntu:20.04:LTS', '2025-05-31', false),
    ('ubuntu', 'jammy',    '22.04', 'Ubuntu:22.04:LTS', '2027-04-30', true),
    ('ubuntu', 'noble',    '24.04', 'Ubuntu:24.04:LTS', '2029-04-30', true),
    ('ubuntu', 'questing', '25.10', 'Ubuntu:25.10',     '2026-07-31', false),
    ('ubuntu', 'resolute', '26.04', 'Ubuntu:26.04:LTS', '2031-04-30', true);

-- One row per upstream advisory record (DSA/DLA/DEBIAN-CVE, USN/LSN/
-- UBUNTU-CVE, ...) that affects at least one supported release.
CREATE TABLE advisories (
    id            text PRIMARY KEY,          -- 'DSA-5532-1', 'DEBIAN-CVE-2024-1234', 'USN-6500-1'
    source        text NOT NULL,             -- 'osv-debian' | 'osv-ubuntu' (later 'debian-tracker', ...)
    -- Canonical key used downstream: the record's CVE (own id, or the CVE a
    -- DEBIAN-CVE-/UBUNTU-CVE- record describes, or a DSA/USN's single CVE);
    -- else the advisory id (e.g. a DSA fixing several CVEs).
    vuln_key      text NOT NULL,
    cve_ids       text[] NOT NULL DEFAULT '{}', -- every CVE the record cites (aliases + upstream)
    aliases       text[] NOT NULL DEFAULT '{}', -- OSV `aliases`
    upstream      text[] NOT NULL DEFAULT '{}', -- OSV `upstream`
    related       text[] NOT NULL DEFAULT '{}', -- OSV `related` (e.g. UBUNTU-CVE <-> USN)
    summary       text,
    details       text,
    severity      text,                      -- record-level distro severity (Ubuntu priority), normalized lowercase
    published_at  timestamptz,
    modified_at   timestamptz NOT NULL,
    withdrawn_at  timestamptz,               -- withdrawn records keep this row but have no advisory_affected rows
    -- Source record trimmed for size: `affected[].versions`,
    -- `ecosystem_specific.binaries` and affected entries for unsupported
    -- releases are dropped (Ubuntu's full records are ~7.9 GB).
    raw           jsonb NOT NULL,
    content_hash  text NOT NULL,             -- sha256 of the normalized form; unchanged => sync skips the row
    synced_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX advisories_vuln_key_idx ON advisories (vuln_key);
CREATE INDEX advisories_cve_ids_idx  ON advisories USING gin (cve_ids);
CREATE INDEX advisories_source_idx   ON advisories (source);

-- Normalized "which source package in which release is affected, fixed in
-- what". One row per (introduced, fixed) pair of an ECOSYSTEM range.
-- Versions are dpkg versions compared in Go (server/internal/debversion),
-- never in SQL.
CREATE TABLE advisory_affected (
    advisory_id     text NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    distro          text NOT NULL,
    release         text NOT NULL,           -- codename, via distro_releases
    source_package  text NOT NULL,           -- advisories are keyed by SOURCE package
    -- 'standard' = the release's normal archive; 'ubuntu-pro' = fix (or
    -- tracking) only in Ubuntu Pro / ESM (OSV `Ubuntu:Pro:<ver>`). Kept
    -- distinct so ESM can be filtered or labelled (DOMAIN_MODEL.md Q9).
    channel         text NOT NULL DEFAULT 'standard',
    introduced      text NOT NULL DEFAULT '', -- '' or '0' = all earlier versions
    fixed_version   text,                    -- NULL = no fix available (yet)
    last_affected   text,                    -- rare OSV alternative to `fixed` (inclusive upper bound)
    distro_severity text,                    -- Debian urgency / Ubuntu priority, lowercase; NULL = not yet assigned
    status          text NOT NULL,           -- 'fixed' | 'unfixed' (OSV has no not_affected/ignored)
    ecosystem       text NOT NULL,           -- OSV ecosystem as published, e.g. 'Ubuntu:Pro:22.04:LTS'
    PRIMARY KEY (advisory_id, distro, release, source_package, channel, introduced),
    CONSTRAINT advisory_affected_channel_ck CHECK (channel IN ('standard', 'ubuntu-pro')),
    CONSTRAINT advisory_affected_status_ck  CHECK (status IN ('fixed', 'unfixed', 'not_affected', 'ignored'))
);
CREATE INDEX advisory_affected_lookup_idx ON advisory_affected (distro, release, source_package);

-- Dirty set for the matcher (§2.6 trigger "advisory sync inserts, updates
-- or withdraws advisory_affected rows"): every (distro, release, source
-- package) whose advisory_affected rows changed, written in the same
-- transaction as the change. The matcher drains it (delete rows with
-- changed_at <= the time it read them) after re-evaluating all
-- software_versions with that source.
CREATE TABLE advisory_changes (
    distro         text NOT NULL,
    release        text NOT NULL,
    source_package text NOT NULL,
    changed_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (distro, release, source_package)
);
CREATE INDEX advisory_changes_changed_at_idx ON advisory_changes (changed_at);

-- Per-CVE enrichment. One row per CVE, however many advisories cite it.
CREATE TABLE cves (
    id               text PRIMARY KEY,       -- 'CVE-2024-1234'
    description      text,
    cvss_v3_score    numeric(3,1),           -- base score computed from the vector
    cvss_v3_vector   text,                   -- from OSV (DEBIAN-CVE / UBUNTU-CVE records)
    epss_score       numeric(6,5),
    epss_percentile  numeric(6,5),
    epss_date        date,
    is_kev           boolean NOT NULL DEFAULT false,
    kev_added_at     date,
    kev_due_date     date,
    kev_ransomware   boolean,                -- knownRansomwareCampaignUse = 'Known'
    updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX cves_kev_idx ON cves (id) WHERE is_kev;

CREATE TABLE feed_sync_state (
    feed              text PRIMARY KEY,      -- 'osv-debian', 'osv-ubuntu', 'cisa-kev', 'first-epss'
    last_success_at   timestamptz,
    last_attempt_at   timestamptz,
    last_full_sync_at timestamptz,           -- OSV: last successful all.zip import
    cursor            text,                  -- OSV: newest `modified` applied; EPSS: score date; KEV: catalogVersion
    etag              text,                  -- last seen ETag of the index/feed file
    config_hash       text,                  -- OSV: hash of the supported release set at the last full sync
    last_error        text,
    stats             jsonb NOT NULL DEFAULT '{}'
);

-- Positive matches per interned package version (§2.6). No row = not known
-- vulnerable. Filled by the matcher (not built yet).
CREATE TABLE software_vulnerabilities (
    software_id      bigint NOT NULL REFERENCES software_versions(id) ON DELETE CASCADE,
    vuln_key         text NOT NULL,          -- CVE id or advisory id
    advisory_ids     text[] NOT NULL,        -- every advisory citing it
    fixed_version    text,                   -- NULL = no fix available
    fix_channel      text,                   -- NULL | 'ubuntu-pro'
    distro_severity  text,
    matcher_version  int NOT NULL,
    matched_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (software_id, vuln_key)
);
CREATE INDEX software_vulnerabilities_vuln_idx ON software_vulnerabilities (vuln_key);

COMMIT;
