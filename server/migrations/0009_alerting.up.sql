-- Alerting: rules, notification channels, the event outbox and the
-- delivery log (docs/ARCHITECTURE.md "Alerting", docs/WEBHOOKS.md).
--
-- The 0001 tables alert_rules / notification_channels / alert_events were
-- never written by anything; they are replaced, not migrated.
--
-- Flow:
--   findings reconcile / agent health job
--     -> alert_events (outbox, same transaction as the transition)
--   alert_evaluate (worker) matches events against alert_rules
--     -> immediate: notifications + notification_deliveries (one per channel)
--     -> digest:    alert_digest_items, flushed by alert_digest into one
--                   notification per rule per interval
--   alert_deliver (worker, River retries) sends one delivery through the
--   channel type's Notifier and records every attempt.
--
-- Ownership: notification_channels, alert_rules, alert_rule_channels are
-- written by Next.js (settings); the dashboard also inserts "send test"
-- notifications/deliveries. Everything else is written by the Go worker.

BEGIN;

DROP TABLE alert_events;
DROP TABLE notification_channels;
DROP TABLE alert_rules;

-- A destination. `type` is a registered notifier type (server/internal/
-- notify: 'webhook' today). Fields a type declares secret live in
-- `secrets`, never in `config`; dashboard queries never select `secrets`
-- (a generated webhook signing secret is shown once, at creation/rotation).
CREATE TABLE notification_channels (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    type        text NOT NULL,
    config      jsonb NOT NULL DEFAULT '{}',
    secrets     jsonb NOT NULL DEFAULT '{}',
    enabled     boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, user_id) -- target of alert_rule_channels' same-owner FK
);
CREATE INDEX notification_channels_user_idx ON notification_channels (user_id);

-- What to alert on. event_types: 'finding.opened' | 'finding.reopened' |
-- 'finding.resolved' | 'agent.stale' | 'agent.recovered' (more later, e.g.
-- exposure events). The severity / KEV filters apply to finding events
-- only. host_ids NULL = all hosts; otherwise events about other hosts are
-- ignored (agent events carry the agent's assigned hosts).
--   min_severity_rank  findings.severity_rank floor, 0 = any
--                      (1 negligible, 2 low, 3 unknown, 4 medium, 5 high, 6 critical)
--   dedup_window_seconds  the same (rule, event type, subject) is not sent
--                      again within this window (0 = no dedup)
--   digest             batch matching events into one notification per
--                      digest_interval_seconds instead of sending at once
CREATE TABLE alert_rules (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                    text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    enabled                 boolean NOT NULL DEFAULT true,
    event_types             text[] NOT NULL CHECK (cardinality(event_types) > 0),
    min_severity_rank       int NOT NULL DEFAULT 0 CHECK (min_severity_rank BETWEEN 0 AND 6),
    kev_only                boolean NOT NULL DEFAULT false,
    host_ids                uuid[],
    dedup_window_seconds    int NOT NULL DEFAULT 3600 CHECK (dedup_window_seconds BETWEEN 0 AND 604800),
    digest                  boolean NOT NULL DEFAULT false,
    digest_interval_seconds int NOT NULL DEFAULT 3600 CHECK (digest_interval_seconds BETWEEN 300 AND 604800),
    last_digest_at          timestamptz,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, user_id)
);
CREATE INDEX alert_rules_user_idx ON alert_rules (user_id) WHERE enabled;

-- Rule -> channels. The composite FKs make a cross-user link impossible.
CREATE TABLE alert_rule_channels (
    rule_id     uuid NOT NULL,
    channel_id  uuid NOT NULL,
    user_id     uuid NOT NULL,
    PRIMARY KEY (rule_id, channel_id),
    FOREIGN KEY (rule_id, user_id) REFERENCES alert_rules (id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (channel_id, user_id) REFERENCES notification_channels (id, user_id) ON DELETE CASCADE
);
CREATE INDEX alert_rule_channels_channel_idx ON alert_rule_channels (channel_id);

-- Outbox of things that happened, written in the transaction that made
-- them happen (and only when the user has an enabled rule for that type).
--   subject   what the event is about, for dedup: 'finding:<host>:<dedup_key>',
--             'agent:<agent id>'
--   payload   the event body as sent (host / agent / finding objects),
--             frozen at the time of the transition
CREATE TABLE alert_events (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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

-- Last time a rule sent (or queued for a digest) a given dedup key
-- ('<event type>|<subject>').
CREATE TABLE alert_dedup (
    rule_id       uuid NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    dedup_key     text NOT NULL,
    last_sent_at  timestamptz NOT NULL,
    PRIMARY KEY (rule_id, dedup_key)
);

-- Matched events waiting for their rule's next digest.
CREATE TABLE alert_digest_items (
    rule_id   uuid NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    event_id  bigint NOT NULL REFERENCES alert_events(id) ON DELETE CASCADE,
    PRIMARY KEY (rule_id, event_id)
);

-- One message to send: kind 'alert' (immediate), 'digest', or 'test' (the
-- dashboard's "send test"; payload built by the worker at send time).
-- payload is the channel-agnostic notification body (notify.Notification),
-- frozen at creation so every channel and every retry sends the same thing.
CREATE TABLE notifications (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rule_id     uuid REFERENCES alert_rules(id) ON DELETE SET NULL,
    kind        text NOT NULL CHECK (kind IN ('alert', 'digest', 'test')),
    event_count int NOT NULL DEFAULT 0,
    summary     text NOT NULL DEFAULT '',
    payload     jsonb,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX notifications_user_idx ON notifications (user_id, created_at DESC);

-- A notification sent to one channel. status:
--   pending   queued, not attempted yet
--   retrying  last attempt failed, River will retry
--   delivered 2xx received
--   failed    permanent error or out of attempts
-- channel_name / channel_type are kept so the log survives a deleted channel.
CREATE TABLE notification_deliveries (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    notification_id  uuid NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
    channel_id       uuid REFERENCES notification_channels(id) ON DELETE SET NULL,
    channel_name     text NOT NULL,
    channel_type     text NOT NULL,
    status           text NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending', 'retrying', 'delivered', 'failed')),
    attempts         int NOT NULL DEFAULT 0,
    last_status_code int,
    last_error       text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    delivered_at     timestamptz
);
CREATE INDEX notification_deliveries_user_idx ON notification_deliveries (user_id, created_at DESC);
CREATE INDEX notification_deliveries_channel_idx ON notification_deliveries (channel_id, created_at DESC);

CREATE TABLE notification_delivery_attempts (
    delivery_id   uuid NOT NULL REFERENCES notification_deliveries(id) ON DELETE CASCADE,
    attempt       int NOT NULL,
    attempted_at  timestamptz NOT NULL DEFAULT now(),
    status_code   int,
    error         text,
    duration_ms   int NOT NULL DEFAULT 0,
    PRIMARY KEY (delivery_id, attempt)
);

-- Last health state the agent_health job saw per agent, so it emits
-- agent.stale / agent.recovered only on a change. "stale" is the dashboard's
-- rule: silent for more than greatest(3 * coalesce(push_interval_seconds,
-- 900), 120) seconds. A new agent's first observation records its state
-- without an event.
CREATE TABLE agent_health (
    agent_id    uuid PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    state       text NOT NULL CHECK (state IN ('online', 'stale')),
    changed_at  timestamptz NOT NULL DEFAULT now()
);

COMMIT;
