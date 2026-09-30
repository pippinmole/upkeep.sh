-- Removes the Alpine releases and what the OSV Alpine sync and the apk
-- matcher derived from them. apk versions are reset to "never
-- evaluated", so a re-up re-imports the feed (first sync) and the
-- matcher sweep re-evaluates them.

BEGIN;

DELETE FROM software_vulnerabilities
WHERE software_id IN (SELECT id FROM software_versions WHERE distro = 'alpine');
UPDATE software_versions SET
    matcher_version = NULL, evaluated_at = NULL, match_source = NULL, match_version = NULL,
    max_fixed_version = NULL
WHERE distro = 'alpine';

DELETE FROM advisories WHERE source = 'osv-alpine'; -- advisory_affected cascades
DELETE FROM advisory_changes WHERE distro = 'alpine';
DELETE FROM feed_sync_state WHERE feed = 'osv-alpine';
DELETE FROM distro_releases WHERE distro = 'alpine';

COMMIT;
