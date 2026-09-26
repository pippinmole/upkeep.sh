-- P1b matcher + findings (DOMAIN_MODEL.md §2.5, §2.6, Q7, Q9).
--
-- software_vulnerabilities is filled by the matcher (server/internal/
-- matcher, store/matching.go) on the worker's `matcher` queue; findings are
-- reconciled per host from it (internal/findings, store/findings.go) on the
-- `findings` queue.

BEGIN;

-- Running kernel release (/proc/sys/kernel/osrelease, payload os.kernel),
-- NULL when the agent predates the kernel collector or it failed. The
-- host's running kernel is its newest snapshot's value (by collected_at).
ALTER TABLE snapshots ADD COLUMN kernel_release text;
CREATE INDEX snapshots_host_collected_idx ON snapshots (host_id, collected_at DESC);

-- What the matcher actually compared for this binary version (written by
-- the matcher, with matcher_version / evaluated_at):
--   match_source   advisory source package: source_name, except kernels,
--                  whose wrapper sources are unwrapped (linux-signed-hwe-6.8
--                  -> linux-hwe-6.8, Debian linux-signed-amd64 -> linux).
--                  NULL = not matched (non-deb, kernel metapackages/headers/
--                  tools/linux-libc-dev, kernels from source-less agents).
--   match_version  the version compared (source_version; the binary version
--                  for unwrapped kernel images).
--   kernel_release for kernel image/module binaries, the `uname -r` they
--                  belong to ("6.8.0-45-generic"); findings are raised only
--                  when it equals the host's running kernel.
ALTER TABLE software_versions
    ADD COLUMN match_source   text,
    ADD COLUMN match_version  text,
    ADD COLUMN kernel_release text;
-- advisory_changes drain: versions per (distro, release, advisory source).
CREATE INDEX software_versions_match_idx ON software_versions (distro, release, match_source)
    WHERE match_source IS NOT NULL;
-- matcher_sweep / reconcile's "anything not yet evaluated?" check.
CREATE INDEX software_versions_unevaluated_idx ON software_versions (id) WHERE matcher_version IS NULL;

-- fix_channel: NULL = no fix available in any channel; 'standard' = fixed
-- in the release's normal archive; 'ubuntu-pro' = the only fix is in Ubuntu
-- Pro / ESM ("fix requires Ubuntu Pro"). fix_advisory_id: the advisory the
-- fixed_version comes from. The table is empty before this migration.
ALTER TABLE software_vulnerabilities
    ADD COLUMN fix_advisory_id text,
    ADD CONSTRAINT software_vulnerabilities_fix_channel_ck
        CHECK (fix_channel IN ('standard', 'ubuntu-pro')),
    ADD CONSTRAINT software_vulnerabilities_fix_ck
        CHECK ((fixed_version IS NULL) = (fix_channel IS NULL));

-- Findings: kind 'vulnerable_package' rows are one per (host, source
-- package, vuln_key), dedup_key = 'pkg:<source>:<vuln_key>'. The columns
-- below are a snapshot taken at the last reconcile (and, for the CVE
-- enrichment and severity, at the last re-rank after a KEV/EPSS sync).
--   severity       display bucket: critical|high|medium|unknown|low|negligible
--   severity_rank  the bucket as an int (1 negligible .. 6 critical), for
--                  alert_rules.min_severity_rank
--   severity_key   severity.Key: ORDER BY severity_key DESC = most urgent first
ALTER TABLE findings
    ADD COLUMN source_package         text,
    ADD COLUMN installed_version      text,
    ADD COLUMN fixed_version          text,
    ADD COLUMN fix_channel            text,
    ADD COLUMN requires_pro           boolean NOT NULL DEFAULT false,
    ADD COLUMN fix_advisory_id        text,
    ADD COLUMN advisory_ids           text[] NOT NULL DEFAULT '{}',
    ADD COLUMN distro_severity        text,
    ADD COLUMN severity               text,
    ADD COLUMN severity_key           bigint NOT NULL DEFAULT 0,
    ADD COLUMN is_kev                 boolean NOT NULL DEFAULT false,
    ADD COLUMN epss_score             numeric(6,5),
    ADD COLUMN epss_percentile        numeric(6,5),
    ADD COLUMN cvss_v3_score          numeric(3,1),
    ADD COLUMN software_ids           bigint[] NOT NULL DEFAULT '{}',
    ADD COLUMN packages               text[] NOT NULL DEFAULT '{}',
    ADD COLUMN kernel_release         text,
    ADD COLUMN running_kernel_unknown boolean NOT NULL DEFAULT false,
    ADD COLUMN reopened_at            timestamptz,
    ADD COLUMN reopen_count           int NOT NULL DEFAULT 0,
    ADD CONSTRAINT findings_status_ck CHECK (status IN ('open', 'resolved')),
    ADD CONSTRAINT findings_fix_channel_ck CHECK (fix_channel IN ('standard', 'ubuntu-pro'));
-- Per-host vulnerability list, most urgent first.
CREATE INDEX findings_host_open_rank_idx ON findings (host_id, severity_key DESC) WHERE status = 'open';
-- Fleet vulnerability pages.
CREATE INDEX findings_open_rank_idx ON findings (severity_key DESC) WHERE status = 'open';

-- Installed kernel image/module packages per host, with whether each is
-- the running kernel (Q7): findings are raised only for the running one
-- (or for all of them while the running kernel is unknown); the others are
-- informational. is_running is NULL when the running kernel is unknown.
CREATE VIEW host_kernel_packages AS
SELECT hs.host_id,
       sv.id             AS software_id,
       sv.name,
       sv.version,
       sv.arch,
       sv.match_source   AS source_package,
       sv.kernel_release,
       rk.kernel_release AS running_kernel_release,
       CASE WHEN rk.kernel_release IS NULL THEN NULL
            ELSE sv.kernel_release = rk.kernel_release END AS is_running,
       hs.first_seen_at,
       (SELECT count(*) FROM software_vulnerabilities sw
         WHERE sw.software_id = sv.id)                                  AS vuln_count,
       (SELECT count(*) FROM software_vulnerabilities sw
         WHERE sw.software_id = sv.id AND sw.fix_channel = 'standard')  AS fixable_count
FROM host_software hs
JOIN software_versions sv ON sv.id = hs.software_id
LEFT JOIN LATERAL (
    SELECT s.kernel_release FROM snapshots s
    WHERE s.host_id = hs.host_id
    ORDER BY s.collected_at DESC LIMIT 1
) rk ON true
WHERE hs.removed_at IS NULL AND sv.kernel_release IS NOT NULL;

-- Per (host, installed binary version) vulnerability summary from the open
-- findings that binary contributes to: for the Packages tab.
CREATE VIEW host_package_vuln_status AS
SELECT f.host_id,
       sid                                    AS software_id,
       count(*)                               AS open_findings,
       max(f.severity_key)                    AS top_severity_key,
       (array_agg(f.severity ORDER BY f.severity_key DESC))[1] AS top_severity,
       count(*) FILTER (WHERE f.is_kev)       AS kev_count,
       count(*) FILTER (WHERE f.fix_channel = 'standard')   AS fixable_count,
       count(*) FILTER (WHERE f.requires_pro)                AS pro_only_count,
       count(*) FILTER (WHERE f.fixed_version IS NULL)       AS unfixed_count
FROM findings f, unnest(f.software_ids) AS sid
WHERE f.status = 'open' AND f.kind = 'vulnerable_package'
GROUP BY f.host_id, sid;

COMMIT;
