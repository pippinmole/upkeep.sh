-- Drops the extra ranges (seq > 0); the next full sync of a language feed
-- keeps only the first again.

BEGIN;

DELETE FROM advisory_affected WHERE seq > 0;
ALTER TABLE advisory_affected DROP CONSTRAINT advisory_affected_pkey;
ALTER TABLE advisory_affected
    ADD PRIMARY KEY (advisory_id, distro, release, source_package, channel, introduced);
ALTER TABLE advisory_affected DROP COLUMN seq;

COMMIT;
