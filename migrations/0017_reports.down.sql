BEGIN;

DELETE FROM notifications WHERE kind = 'report';
DROP INDEX notifications_report_idx;
ALTER TABLE notifications
    DROP COLUMN report_id,
    DROP CONSTRAINT notifications_kind_check,
    ADD CONSTRAINT notifications_kind_check CHECK (kind IN ('alert', 'digest', 'test'));
DROP TABLE reports;
DROP TABLE report_schedule_channels;
DROP TABLE report_schedules;

COMMIT;
