-- Back to the 0009 / 0015 event rules. Condition rules, alert instances
-- and their events are dropped (they have no event-rule equivalent).
BEGIN;

DROP TRIGGER workspaces_seed_default_alert_rules ON workspaces;
DROP FUNCTION workspaces_seed_default_alert_rules();
DROP FUNCTION seed_default_alert_rules(uuid);

DROP TABLE alert_digest_items;
DROP TABLE alert_events;
DROP TABLE alert_instances;

DELETE FROM alert_rules;
ALTER TABLE alert_rules
    DROP CONSTRAINT alert_rules_default_uq,
    DROP COLUMN default_key,
    DROP COLUMN notify_on_resolve,
    DROP COLUMN condition,
    ADD COLUMN event_types text[] NOT NULL CHECK (cardinality(event_types) > 0),
    ADD COLUMN min_severity_rank int NOT NULL DEFAULT 0 CHECK (min_severity_rank BETWEEN 0 AND 6),
    ADD COLUMN kev_only boolean NOT NULL DEFAULT false,
    ADD COLUMN dedup_window_seconds int NOT NULL DEFAULT 3600 CHECK (dedup_window_seconds BETWEEN 0 AND 604800),
    ADD COLUMN finding_kinds text[] NOT NULL DEFAULT ARRAY['vulnerable_package', 'vulnerable_image'],
    ADD CONSTRAINT alert_rules_finding_kinds_ck CHECK (
        cardinality(finding_kinds) > 0
        AND finding_kinds <@ ARRAY['vulnerable_package', 'vulnerable_image']);

CREATE TABLE alert_events (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    type          text NOT NULL,
    subject       text NOT NULL,
    occurred_at   timestamptz NOT NULL DEFAULT now(),
    host_ids      uuid[] NOT NULL DEFAULT '{}',
    severity_rank int,
    is_kev        boolean NOT NULL DEFAULT false,
    payload       jsonb NOT NULL DEFAULT '{}',
    processed_at  timestamptz
);
CREATE INDEX alert_events_pending_idx ON alert_events (id) WHERE processed_at IS NULL;
CREATE INDEX alert_events_processed_idx ON alert_events (processed_at) WHERE processed_at IS NOT NULL;

CREATE TABLE alert_dedup (
    rule_id       uuid NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    dedup_key     text NOT NULL,
    last_sent_at  timestamptz NOT NULL,
    PRIMARY KEY (rule_id, dedup_key)
);

CREATE TABLE alert_digest_items (
    rule_id   uuid NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    event_id  bigint NOT NULL REFERENCES alert_events(id) ON DELETE CASCADE,
    PRIMARY KEY (rule_id, event_id)
);

CREATE TABLE agent_health (
    agent_id    uuid PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    state       text NOT NULL CHECK (state IN ('online', 'stale')),
    changed_at  timestamptz NOT NULL DEFAULT now()
);

COMMIT;
