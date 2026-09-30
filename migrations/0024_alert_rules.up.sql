-- Condition rules and stateful alerts (docs/ALERTING.md). Replaces the
-- event rules of 0009 / 0015: a rule is now a typed condition over a
-- host's current state, evaluated by the worker (alert_rules_evaluate) into
-- alert_instances, whose transitions feed the existing notification
-- pipeline through alert_events.
--
-- Destructive (nothing is deployed): existing event rules, their pending
-- events, digest items and dedup marks are dropped. Channels, the delivery
-- log and report schedules are untouched.
--
-- Ownership (per workspace since 0023, like hosts and channels):
--   alert_rules, alert_rule_channels   Next.js (Settings -> Alert rules)
--   alert_instances, alert_events,
--   alert_digest_items, alert_rules.last_digest_at   Go (worker)

BEGIN;

DROP TABLE alert_digest_items;
DROP TABLE alert_dedup;
DROP TABLE alert_events;
DROP TABLE agent_health;

DELETE FROM alert_rules;
ALTER TABLE alert_rules
    DROP CONSTRAINT alert_rules_finding_kinds_ck,
    DROP COLUMN finding_kinds,
    DROP COLUMN event_types,
    DROP COLUMN min_severity_rank,
    DROP COLUMN kev_only,
    DROP COLUMN dedup_window_seconds,
    -- {"property", "operator", "value"?, "options"?}; validated and
    -- normalised by internal/alerting (Go) and web/src/lib/alert-conditions.ts
    -- from the same catalogue. The worker skips a rule whose condition
    -- doesn't validate.
    ADD COLUMN condition jsonb NOT NULL CHECK (
        jsonb_typeof(condition) = 'object'
        AND jsonb_typeof(condition -> 'property') = 'string'
        AND jsonb_typeof(condition -> 'operator') = 'string'),
    -- Also send when an alert resolves (cleared); silent resolutions (rule
    -- edited / disabled / deleted, host out of scope or archived) never do.
    ADD COLUMN notify_on_resolve boolean NOT NULL DEFAULT true,
    -- Set on rules created by seed_default_alert_rules, so seeding never
    -- duplicates one. A deleted default isn't recreated.
    ADD COLUMN default_key text,
    ADD CONSTRAINT alert_rules_default_uq UNIQUE (workspace_id, default_key);
-- host_ids stays: NULL = all hosts (including future ones), else these.

-- One firing episode of a rule on a host, per subject (the port, package,
-- finding or collector; '' for host-level properties). A key fires at most
-- once at a time (alert_instances_firing_uq); firing again after a
-- resolution is a new row, so this table is also the history.
--   rule_name   kept so history survives the rule's deletion (rule_id NULL)
--   condition   the rule's condition when this instance last matched: a
--               resolution after the condition was edited is rule_changed
--               (silent), not cleared
--   title       one line, e.g. "Port 22/tcp is listening"
--   details     property-specific JSON (addresses, versions, error, ...)
CREATE TABLE alert_instances (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id     uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    rule_id          uuid REFERENCES alert_rules(id) ON DELETE SET NULL,
    rule_name        text NOT NULL,
    host_id          uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    subject          text NOT NULL DEFAULT '',
    property         text NOT NULL,
    condition        jsonb NOT NULL,
    state            text NOT NULL CHECK (state IN ('firing', 'resolved')),
    title            text NOT NULL,
    details          jsonb NOT NULL DEFAULT '{}',
    fired_at         timestamptz NOT NULL,
    updated_at       timestamptz NOT NULL, -- title / details / condition last refreshed
    resolved_at      timestamptz,
    resolved_reason  text CHECK (resolved_reason IN
                     ('cleared', 'rule_changed', 'rule_disabled', 'rule_deleted', 'out_of_scope', 'host_archived')),
    CONSTRAINT alert_instances_state_ck CHECK (
        (state = 'firing' AND resolved_at IS NULL AND resolved_reason IS NULL)
        OR (state = 'resolved' AND resolved_at IS NOT NULL AND resolved_reason IS NOT NULL))
);
CREATE UNIQUE INDEX alert_instances_firing_uq ON alert_instances (rule_id, host_id, subject) WHERE state = 'firing';
CREATE INDEX alert_instances_firing_orphan_idx ON alert_instances (id) WHERE state = 'firing' AND rule_id IS NULL;
CREATE INDEX alert_instances_host_firing_idx ON alert_instances (host_id) WHERE state = 'firing';
CREATE INDEX alert_instances_workspace_idx ON alert_instances (workspace_id, fired_at DESC);
CREATE INDEX alert_instances_rule_idx ON alert_instances (rule_id, fired_at DESC);

-- Outbox of instance transitions that should notify, written in the
-- evaluation transaction and drained by alert_evaluate (as in 0009).
-- payload is the notify.Event body frozen at the transition.
CREATE TABLE alert_events (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    rule_id       uuid NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    instance_id   uuid NOT NULL REFERENCES alert_instances(id) ON DELETE CASCADE,
    type          text NOT NULL CHECK (type IN ('alert.firing', 'alert.resolved')),
    occurred_at   timestamptz NOT NULL DEFAULT now(),
    payload       jsonb NOT NULL DEFAULT '{}',
    processed_at  timestamptz
);
CREATE INDEX alert_events_pending_idx ON alert_events (id) WHERE processed_at IS NULL;
CREATE INDEX alert_events_processed_idx ON alert_events (processed_at) WHERE processed_at IS NOT NULL;
CREATE INDEX alert_events_instance_idx ON alert_events (instance_id);

-- Matched events waiting for their rule's next digest (as in 0009).
CREATE TABLE alert_digest_items (
    rule_id   uuid NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    event_id  bigint NOT NULL REFERENCES alert_events(id) ON DELETE CASCADE,
    PRIMARY KEY (rule_id, event_id)
);

-- Default rules for one workspace. Idempotent (default_key). The condition
-- must validate in internal/alerting (TestDefaultRulesValidate).
CREATE FUNCTION seed_default_alert_rules(p_workspace uuid)
RETURNS void LANGUAGE sql AS $$
    INSERT INTO alert_rules (workspace_id, name, condition, default_key)
    VALUES (p_workspace, 'SSH listening (port 22)',
            '{"property": "listening_port", "operator": "in", "value": [22], "options": {"bind": "non_loopback", "protocol": "tcp"}}',
            'ssh_port_22')
    ON CONFLICT (workspace_id, default_key) DO NOTHING
$$;

-- Every new workspace gets the defaults (an install has one, created by
-- 0023; seeded below).
CREATE FUNCTION workspaces_seed_default_alert_rules()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM seed_default_alert_rules(NEW.id);
    RETURN NEW;
END $$;
CREATE TRIGGER workspaces_seed_default_alert_rules AFTER INSERT ON workspaces
    FOR EACH ROW EXECUTE FUNCTION workspaces_seed_default_alert_rules();

SELECT seed_default_alert_rules(id) FROM workspaces;

COMMIT;
