-- Scheduled estate reports: schedules, their channels, and the stored
-- report of every run (docs/tasks/phase-1-7-reports.md,
-- docs/decisions/scheduled-reports.md, docs/ARCHITECTURE.md "Reports").
--
-- Flow:
--   report_due (worker, 1m) finds schedules with next_run_at <= now
--     -> builds the snapshot (server/internal/reports) in one read tx
--     -> reports row, compared with the schedule's previous report
--     -> a 'report' notification + one notification_deliveries row per
--        schedule channel + alert_deliver jobs (same tx), next_run_at
--        advanced in the schedule's timezone
--   "Send now" (dashboard) inserts a River job for one schedule; the worker
--   runs it exactly like a scheduled run (trigger 'manual'), without
--   touching next_run_at.
--
-- Ownership: report_schedules (except next_run_at / last_run_at) and
-- report_schedule_channels are written by Next.js (Settings -> Notification
-- settings). reports, next_run_at and last_run_at are written by the Go
-- worker.

BEGIN;

-- When to send a whole-estate report (every non-archived host; no host
-- scope yet). Weekly: weekday (0 = Sunday .. 6 = Saturday, like
-- time.Weekday and JS getDay) and hour. Monthly: day_of_month and hour.
-- day_of_month stops at 28 so every month has the day: no "31st in
-- February" clamping rule to explain or get wrong.
--   timezone     IANA name (e.g. 'Europe/London'); the hour is local time
--                there, so DST moves the UTC instant, not the local hour.
--                Validated by Next.js on write and by the worker when it
--                computes next_run_at (Postgres can't CHECK it).
--   next_run_at  the next scheduled run. NULL = not computed yet: the
--                worker computes it (from now, in the timezone) and
--                doesn't run the schedule on that pass. Next.js inserts
--                NULL and resets it to NULL when cadence / day / hour /
--                timezone change, so the worker recomputes it.
--   last_run_at  when the last report (scheduled or manual) was generated.
CREATE TABLE report_schedules (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    enabled       boolean NOT NULL DEFAULT true,
    cadence       text NOT NULL CHECK (cadence IN ('weekly', 'monthly')),
    weekday       int CHECK (weekday BETWEEN 0 AND 6),
    day_of_month  int CHECK (day_of_month BETWEEN 1 AND 28),
    hour          int NOT NULL CHECK (hour BETWEEN 0 AND 23),
    timezone      text NOT NULL CHECK (timezone <> ''),
    next_run_at   timestamptz,
    last_run_at   timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, user_id), -- target of the same-owner FKs below
    CONSTRAINT report_schedules_day_ck CHECK (
        (cadence = 'weekly' AND weekday IS NOT NULL AND day_of_month IS NULL)
        OR (cadence = 'monthly' AND day_of_month IS NOT NULL AND weekday IS NULL))
);
CREATE INDEX report_schedules_user_idx ON report_schedules (user_id);
-- report_due: enabled schedules that are due or not computed yet
-- (WHERE enabled AND (next_run_at IS NULL OR next_run_at <= now())).
CREATE INDEX report_schedules_due_idx ON report_schedules (next_run_at) WHERE enabled;

-- Schedule -> channels. The composite FKs make a cross-user link
-- impossible, as for alert_rule_channels.
CREATE TABLE report_schedule_channels (
    schedule_id  uuid NOT NULL,
    channel_id   uuid NOT NULL,
    user_id      uuid NOT NULL,
    PRIMARY KEY (schedule_id, channel_id),
    FOREIGN KEY (schedule_id, user_id) REFERENCES report_schedules (id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (channel_id, user_id) REFERENCES notification_channels (id, user_id) ON DELETE CASCADE
);
CREATE INDEX report_schedule_channels_channel_idx ON report_schedule_channels (channel_id);

-- One generated report, stored whole so every channel and every retry
-- sends the same content, the dashboard can list past reports, and the
-- next run can compare against it. A report belongs to its schedule:
-- deleting the schedule deletes its history (the delivery log keeps its
-- rows; notifications.report_id is set NULL).
--   period_start / period_end  what the "since last report" numbers cover:
--                   the previous report's generated_at (or the schedule's
--                   nominal period when there is none) .. generated_at
--   ranking_version reports.RankingVersion when built; comparison with a
--                   previous report of another version is suppressed
--   snapshot        the reports.Snapshot JSON (schema_version inside);
--                   the fixture is web/src/lib/report-snapshot.example.json
--   previous_report_id  the report this one was compared with, if any
--   trigger         'scheduled' (report_due) or 'manual' ("Send now");
--                   both count as the previous report for the next run
-- Pruned after a year by alert_prune, keeping the latest per schedule.
CREATE TABLE reports (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    schedule_id         uuid NOT NULL,
    user_id             uuid NOT NULL,
    generated_at        timestamptz NOT NULL DEFAULT now(),
    period_start        timestamptz NOT NULL,
    period_end          timestamptz NOT NULL,
    ranking_version     int NOT NULL,
    snapshot            jsonb NOT NULL,
    previous_report_id  uuid REFERENCES reports(id) ON DELETE SET NULL,
    trigger             text NOT NULL CHECK (trigger IN ('scheduled', 'manual')),
    FOREIGN KEY (schedule_id, user_id) REFERENCES report_schedules (id, user_id) ON DELETE CASCADE,
    CHECK (period_start <= period_end)
);
-- Past reports per schedule, and "the previous report" lookup.
CREATE INDEX reports_schedule_idx ON reports (schedule_id, generated_at DESC);
CREATE INDEX reports_user_idx ON reports (user_id, generated_at DESC);
-- ON DELETE SET NULL of previous_report_id (pruning, schedule deletion).
CREATE INDEX reports_previous_idx ON reports (previous_report_id) WHERE previous_report_id IS NOT NULL;

-- Report notifications: kind 'report', pointing at the stored report the
-- deliveries render (the snapshot is not copied into payload). NULL for
-- every other kind, and after the report is deleted with its schedule; a
-- delivery still pending then fails permanently. Notifications are pruned
-- at 90 days and reports at a year, so pruning never orphans one.
ALTER TABLE notifications
    DROP CONSTRAINT notifications_kind_check,
    ADD CONSTRAINT notifications_kind_check CHECK (kind IN ('alert', 'digest', 'test', 'report')),
    ADD COLUMN report_id uuid REFERENCES reports(id) ON DELETE SET NULL;
CREATE INDEX notifications_report_idx ON notifications (report_id) WHERE report_id IS NOT NULL;

COMMIT;
