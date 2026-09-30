BEGIN;

DROP VIEW IF EXISTS host_package_vuln_status;
DROP VIEW IF EXISTS host_kernel_packages;

DROP INDEX IF EXISTS findings_open_rank_idx;
DROP INDEX IF EXISTS findings_host_open_rank_idx;
ALTER TABLE findings
    DROP CONSTRAINT IF EXISTS findings_fix_channel_ck,
    DROP CONSTRAINT IF EXISTS findings_status_ck,
    DROP COLUMN source_package,
    DROP COLUMN installed_version,
    DROP COLUMN fixed_version,
    DROP COLUMN fix_channel,
    DROP COLUMN requires_pro,
    DROP COLUMN fix_advisory_id,
    DROP COLUMN advisory_ids,
    DROP COLUMN distro_severity,
    DROP COLUMN severity,
    DROP COLUMN severity_key,
    DROP COLUMN is_kev,
    DROP COLUMN epss_score,
    DROP COLUMN epss_percentile,
    DROP COLUMN cvss_v3_score,
    DROP COLUMN software_ids,
    DROP COLUMN packages,
    DROP COLUMN kernel_release,
    DROP COLUMN running_kernel_unknown,
    DROP COLUMN reopened_at,
    DROP COLUMN reopen_count;

ALTER TABLE software_vulnerabilities
    DROP CONSTRAINT IF EXISTS software_vulnerabilities_fix_ck,
    DROP CONSTRAINT IF EXISTS software_vulnerabilities_fix_channel_ck,
    DROP COLUMN fix_advisory_id;

DROP INDEX IF EXISTS software_versions_unevaluated_idx;
DROP INDEX IF EXISTS software_versions_match_idx;
ALTER TABLE software_versions
    DROP COLUMN match_source,
    DROP COLUMN match_version,
    DROP COLUMN kernel_release;

DROP INDEX IF EXISTS snapshots_host_collected_idx;
ALTER TABLE snapshots DROP COLUMN kernel_release;

COMMIT;
