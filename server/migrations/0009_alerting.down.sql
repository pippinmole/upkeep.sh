BEGIN;

DROP TABLE agent_health;
DROP TABLE notification_delivery_attempts;
DROP TABLE notification_deliveries;
DROP TABLE notifications;
DROP TABLE alert_digest_items;
DROP TABLE alert_dedup;
DROP TABLE alert_events;
DROP TABLE alert_rule_channels;
DROP TABLE alert_rules;
DROP TABLE notification_channels;

-- The unused 0001 shapes.
CREATE TABLE alert_rules (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind          text NOT NULL,
    min_severity_rank int NOT NULL DEFAULT 0,
    digest        boolean NOT NULL DEFAULT false,
    enabled       boolean NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE notification_channels (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    alert_rule_id uuid REFERENCES alert_rules(id) ON DELETE CASCADE,
    kind          text NOT NULL,
    config        jsonb NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE alert_events (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id        uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    channel_id        uuid NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    event_type        text NOT NULL,
    sent_at           timestamptz,
    delivery_error    text,
    created_at        timestamptz NOT NULL DEFAULT now()
);

COMMIT;
