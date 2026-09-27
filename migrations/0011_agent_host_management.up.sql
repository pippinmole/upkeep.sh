-- Agent and host management (DOMAIN_MODEL.md §4.3 "Management", Q12).
--
-- 1. Credential rotation (PROTOCOL.md "Credential rotation"): the agent
--    calls POST /v1/agent/rotate with its current secret and gets a new
--    one. The secret it authenticated with stays valid as the previous
--    secret until previous_expires_at (a short grace window), or until the
--    new secret is first used, whichever comes first, so an agent that
--    crashes between receiving and persisting the new secret isn't locked
--    out. rotate_requested_at is set by the dashboard's "Rotate
--    credentials"; the server signals the agent on its next push.
-- 2. Host lifecycle: archive (hidden from lists and fleet views, history
--    kept), merge a flagged duplicate into its original (merged_into), and
--    "not a duplicate" (duplicate_dismissed_of stops re-flagging).
-- 3. mgmt_* functions: every dashboard mutation on these Go-owned tables,
--    scoped by user id. Both the dashboard (server actions) and the Go
--    integration tests call them, so there is one implementation.

BEGIN;

ALTER TABLE agent_credentials
    ADD COLUMN previous_secret_hash text,
    ADD COLUMN previous_expires_at  timestamptz,
    ADD COLUMN rotate_requested_at  timestamptz,
    ADD CONSTRAINT agent_credentials_previous_ck
        CHECK ((previous_secret_hash IS NULL) = (previous_expires_at IS NULL));

--   archived_at             set: hidden from host lists, the overview and
--                           fleet views; snapshots, inventory and findings
--                           are kept (and still shown on the host's pages).
--   merged_into             set together with archived_at when this host
--                           was merged into another (its duplicate flag
--                           resolved as "same machine").
--   duplicate_dismissed_of  the host a duplicate flag was dismissed for
--                           ("not a duplicate"); ingest won't re-flag this
--                           host against that one.
ALTER TABLE hosts
    ADD COLUMN archived_at            timestamptz,
    ADD COLUMN merged_into            uuid REFERENCES hosts(id) ON DELETE SET NULL,
    ADD COLUMN duplicate_dismissed_of uuid REFERENCES hosts(id) ON DELETE SET NULL,
    ADD CONSTRAINT hosts_merged_archived_ck CHECK (merged_into IS NULL OR archived_at IS NOT NULL);

-- The worker's credential_cleanup job deletes expired tokens.
CREATE INDEX enrollment_tokens_expires_at_idx ON enrollment_tokens (expires_at);

-- mgmt_agent_active mirrors store.activeAgentSQL (server/internal/store/
-- agents.go): not revoked and seen within max(3 x push interval, 2 min),
-- interval defaulting to 15 min. Keep the two in sync.
CREATE FUNCTION mgmt_agent_active(p_revoked_at timestamptz, p_last_seen_at timestamptz, p_interval int)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT p_revoked_at IS NULL AND p_last_seen_at IS NOT NULL
       AND p_last_seen_at >= now() - make_interval(secs => GREATEST(3 * COALESCE(p_interval, 900), 120))
$$;

-- All mgmt_* functions return a status: 'ok', 'not_found' (no such row
-- for this user: another user's id looks exactly like a missing one), or
-- a reason the action isn't allowed in the current state.

-- Revoke an agent: its credential is refused from now on (ingest and
-- rotation return 401). Irreversible; the agent's hosts and history stay.
CREATE FUNCTION mgmt_revoke_agent(p_user uuid, p_agent uuid)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    UPDATE agents SET revoked_at = COALESCE(revoked_at, now())
    WHERE id = p_agent AND user_id = p_user;
    IF NOT FOUND THEN RETURN 'not_found'; END IF;
    UPDATE agent_credentials SET rotate_requested_at = NULL, previous_secret_hash = NULL, previous_expires_at = NULL
    WHERE agent_id = p_agent;
    RETURN 'ok';
END $$;

-- Ask the agent to rotate its credential on its next push.
CREATE FUNCTION mgmt_request_rotation(p_user uuid, p_agent uuid)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    v_revoked timestamptz;
BEGIN
    SELECT revoked_at INTO v_revoked FROM agents WHERE id = p_agent AND user_id = p_user;
    IF NOT FOUND THEN RETURN 'not_found'; END IF;
    IF v_revoked IS NOT NULL THEN RETURN 'revoked'; END IF;
    UPDATE agent_credentials SET rotate_requested_at = COALESCE(rotate_requested_at, now())
    WHERE agent_id = p_agent;
    RETURN 'ok';
END $$;

-- Set (or clear, with NULL / blank) a host's display label. hostname stays
-- what the agent reports.
CREATE FUNCTION mgmt_rename_host(p_user uuid, p_host uuid, p_label text)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    UPDATE hosts SET label = NULLIF(left(btrim(p_label), 100), '')
    WHERE id = p_host AND user_id = p_user;
    RETURN CASE WHEN FOUND THEN 'ok' ELSE 'not_found' END;
END $$;

-- Archive / unarchive. A merged host stays archived (unarchiving it would
-- leave a host with no agents next to the one it was merged into).
CREATE FUNCTION mgmt_set_host_archived(p_user uuid, p_host uuid, p_archived boolean)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    v_merged uuid;
BEGIN
    SELECT merged_into INTO v_merged FROM hosts WHERE id = p_host AND user_id = p_user FOR UPDATE;
    IF NOT FOUND THEN RETURN 'not_found'; END IF;
    IF v_merged IS NOT NULL THEN RETURN 'merged'; END IF;
    UPDATE hosts SET archived_at = CASE WHEN p_archived THEN COALESCE(archived_at, now()) END
    WHERE id = p_host;
    RETURN 'ok';
END $$;

-- Hard delete, cascading to snapshots, inventory, findings, identities and
-- assignments. p_confirm must equal the hostname (typed confirmation,
-- checked here as well as in the UI).
CREATE FUNCTION mgmt_delete_host(p_user uuid, p_host uuid, p_confirm text)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    v_hostname text;
BEGIN
    SELECT hostname INTO v_hostname FROM hosts WHERE id = p_host AND user_id = p_user FOR UPDATE;
    IF NOT FOUND THEN RETURN 'not_found'; END IF;
    IF p_confirm IS DISTINCT FROM v_hostname THEN RETURN 'confirmation_mismatch'; END IF;
    DELETE FROM hosts WHERE id = p_host;
    RETURN 'ok';
END $$;

-- "Not a duplicate": clear the flag and remember the dismissal, so the
-- next push doesn't flag it against the same host again.
CREATE FUNCTION mgmt_dismiss_duplicate(p_user uuid, p_host uuid)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    v_dup uuid;
BEGIN
    SELECT duplicate_of INTO v_dup FROM hosts WHERE id = p_host AND user_id = p_user FOR UPDATE;
    IF NOT FOUND THEN RETURN 'not_found'; END IF;
    IF v_dup IS NULL THEN RETURN 'not_flagged'; END IF;
    UPDATE hosts SET duplicate_dismissed_of = duplicate_of, duplicate_of = NULL WHERE id = p_host;
    RETURN 'ok';
END $$;

-- Merge a flagged duplicate into the host it duplicates ("same machine";
-- typically an agent reinstalled faster than the old one went inactive).
-- The duplicate's assignments move to the original, so its agents'
-- future pushes land on the original and continue its inventory ranges;
-- its identities move too. The duplicate's own history (snapshots,
-- host_software ranges, findings) is NOT moved: it stays on the
-- duplicate, which is archived with merged_into set. Moving it would mean
-- splicing two overlapping sets of validity ranges and colliding findings
-- (UNIQUE (host_id, dedup_key)); the duplicate usually has minutes of
-- history, so keeping it separate is the safe choice.
CREATE FUNCTION mgmt_merge_host(p_user uuid, p_duplicate uuid, p_original uuid)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    d hosts%ROWTYPE;
    o hosts%ROWTYPE;
BEGIN
    IF p_duplicate = p_original THEN RETURN 'not_flagged'; END IF;
    -- Lock order matches ingest (agent row, then hosts), so a push from
    -- one of the duplicate's agents either finishes before the merge or
    -- resolves after it, onto the original.
    PERFORM 1 FROM agents
    WHERE user_id = p_user AND id IN (SELECT agent_id FROM agent_hosts WHERE host_id = p_duplicate)
    ORDER BY id FOR UPDATE;
    PERFORM 1 FROM hosts WHERE id IN (p_duplicate, p_original) AND user_id = p_user ORDER BY id FOR UPDATE;

    SELECT * INTO d FROM hosts WHERE id = p_duplicate AND user_id = p_user;
    IF NOT FOUND THEN RETURN 'not_found'; END IF;
    SELECT * INTO o FROM hosts WHERE id = p_original AND user_id = p_user;
    IF NOT FOUND THEN RETURN 'not_found'; END IF;
    IF d.duplicate_of IS DISTINCT FROM o.id THEN RETURN 'not_flagged'; END IF;
    IF d.archived_at IS NOT NULL OR o.archived_at IS NOT NULL THEN RETURN 'archived'; END IF;

    -- An agent already collecting the original just drops its duplicate
    -- assignment; every other assignment moves (one local host per agent
    -- still holds: the moved row is that agent's only local one).
    UPDATE agent_hosts ah SET host_id = o.id
    WHERE ah.host_id = d.id
      AND NOT EXISTS (SELECT 1 FROM agent_hosts x WHERE x.agent_id = ah.agent_id AND x.host_id = o.id);
    DELETE FROM agent_hosts WHERE host_id = d.id;

    UPDATE host_identities SET host_id = o.id WHERE host_id = d.id;
    -- Hosts flagged as duplicates of the duplicate now point at the original.
    UPDATE hosts SET duplicate_of = o.id WHERE duplicate_of = d.id AND id <> o.id;
    UPDATE hosts SET last_seen_at = GREATEST(last_seen_at, d.last_seen_at) WHERE id = o.id;
    UPDATE hosts SET archived_at = now(), merged_into = o.id, duplicate_of = NULL WHERE id = d.id;
    RETURN 'ok';
END $$;

-- Remove an agent's assignment to a host. Only for an agent that is no
-- longer active (revoked, or silent past the active window): an active
-- agent's next push would just re-attach it. The host and its history stay.
CREATE FUNCTION mgmt_detach_host(p_user uuid, p_agent uuid, p_host uuid)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    a agents%ROWTYPE;
BEGIN
    SELECT * INTO a FROM agents WHERE id = p_agent AND user_id = p_user FOR UPDATE;
    IF NOT FOUND THEN RETURN 'not_found'; END IF;
    IF mgmt_agent_active(a.revoked_at, a.last_seen_at, a.push_interval_seconds) THEN RETURN 'agent_active'; END IF;
    DELETE FROM agent_hosts ah USING hosts h
    WHERE ah.agent_id = p_agent AND ah.host_id = p_host AND h.id = ah.host_id AND h.user_id = p_user;
    RETURN CASE WHEN FOUND THEN 'ok' ELSE 'not_found' END;
END $$;

COMMIT;
