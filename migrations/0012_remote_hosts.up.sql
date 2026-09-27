-- Remote hosts over SSH (DOMAIN_MODEL.md §4.2, Q3-Q5 resolved 2026-09-27).
--
-- A remote host is added in the dashboard ("Add host" -> "Reach it from an
-- existing agent"): the host row and its ssh assignment are created up
-- front, and the agent picks the assignment up from GET /v1/agent/config.
-- The agent reads the remote machine over read-only SFTP with its own key
-- pair; the private key never leaves the agent's data directory, and the
-- server only stores the public half (agents.ssh_public_key) so the
-- dashboard can show it for authorized_keys.
--
-- Host keys are pinned by the user, not trusted on first use: the agent
-- connects, reports the key the host presented (POST /v1/agent/status ->
-- host_key_pending), and only connects for real once the user confirmed
-- that fingerprint in the dashboard (host_key). A later key change is
-- reported the same way and blocks collection until confirmed again.

BEGIN;

-- The agent's SSH public key, authorized_keys format ("ssh-ed25519 AAAA...").
-- NULL: an agent that predates remote collection (not offered as a remote
-- collector in the dashboard).
ALTER TABLE agents ADD COLUMN ssh_public_key text;

--   port, username       ssh connection settings (address already exists).
--   host_key             the confirmed host key, authorized_keys format
--                        without a comment; NULL until confirmed.
--   host_key_pending     the key the host last presented when it differed
--                        from host_key (or none was confirmed yet).
--   last_attempt_at      the agent's last connection attempt (status report).
--   last_error_code      machine-readable last_error ('host_key_unconfirmed',
--                        'host_key_mismatch', 'auth_failed', 'unreachable',
--                        'sftp_failed', 'push_failed'); NULL when healthy.
ALTER TABLE agent_hosts
    ADD COLUMN port             int CHECK (port BETWEEN 1 AND 65535),
    ADD COLUMN username         text,
    ADD COLUMN host_key         text,
    ADD COLUMN host_key_pending text,
    ADD COLUMN last_attempt_at  timestamptz,
    ADD COLUMN last_error_code  text,
    ADD CONSTRAINT agent_hosts_remote_ck CHECK (
        mode = 'local'
        OR (address IS NOT NULL AND port IS NOT NULL AND username IS NOT NULL)
    );

-- Add a remote (ssh) host collected by one of the user's agents. Creates
-- the host (hostname = the address until the first push reports the real
-- one; label = p_label) and the assignment, whose target_ref is the host
-- id. Returns 'ok:<host id>' on success.
CREATE FUNCTION mgmt_add_remote_host(p_user uuid, p_agent uuid, p_address text, p_port int,
                                     p_username text, p_label text)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    a agents%ROWTYPE;
    v_address  text := btrim(p_address);
    v_username text := btrim(p_username);
    v_host     uuid;
BEGIN
    SELECT * INTO a FROM agents WHERE id = p_agent AND user_id = p_user FOR UPDATE;
    IF NOT FOUND THEN RETURN 'not_found'; END IF;
    IF a.revoked_at IS NOT NULL THEN RETURN 'revoked'; END IF;
    IF a.ssh_public_key IS NULL THEN RETURN 'agent_no_ssh'; END IF;
    -- Hostname or IP literal (v4, or v6 without brackets): no spaces, no
    -- user@ or :port, nothing a shell or ssh option parser would read.
    IF v_address IS NULL OR v_address !~ '^[A-Za-z0-9._:-]{1,253}$' OR v_address ~ '^-' THEN
        RETURN 'invalid_address';
    END IF;
    IF p_port IS NULL OR p_port NOT BETWEEN 1 AND 65535 THEN RETURN 'invalid_port'; END IF;
    IF v_username IS NULL OR v_username !~ '^[a-z_][a-z0-9_.-]{0,31}$' THEN RETURN 'invalid_username'; END IF;
    IF EXISTS (SELECT 1 FROM agent_hosts
               WHERE agent_id = p_agent AND mode = 'ssh' AND lower(address) = lower(v_address) AND port = p_port) THEN
        RETURN 'duplicate_target';
    END IF;

    INSERT INTO hosts (user_id, hostname, label)
    VALUES (p_user, lower(v_address), NULLIF(left(btrim(p_label), 100), ''))
    RETURNING id INTO v_host;
    INSERT INTO agent_hosts (agent_id, host_id, mode, target_ref, address, port, username)
    VALUES (p_agent, v_host, 'ssh', v_host::text, lower(v_address), p_port, v_username);
    RETURN 'ok:' || v_host;
END $$;

-- Confirm the host key the agent reported for a remote assignment. The
-- caller passes the key it showed the user, so a key that changed between
-- display and click is not confirmed by accident.
CREATE FUNCTION mgmt_confirm_host_key(p_user uuid, p_agent uuid, p_host uuid, p_key text)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    v_pending text;
BEGIN
    SELECT ah.host_key_pending INTO v_pending
    FROM agent_hosts ah JOIN hosts h ON h.id = ah.host_id
    WHERE ah.agent_id = p_agent AND ah.host_id = p_host AND ah.mode <> 'local' AND h.user_id = p_user
    FOR UPDATE OF ah;
    IF NOT FOUND THEN RETURN 'not_found'; END IF;
    IF v_pending IS NULL OR v_pending IS DISTINCT FROM p_key THEN RETURN 'host_key_changed'; END IF;
    UPDATE agent_hosts
    SET host_key = v_pending, host_key_pending = NULL, last_error = NULL, last_error_code = NULL
    WHERE agent_id = p_agent AND host_id = p_host;
    RETURN 'ok';
END $$;

-- Remove a remote assignment (the agent stops collecting that host on its
-- next config fetch). Unlike mgmt_detach_host this is allowed while the
-- agent is active: a remote assignment is never re-created by a push. The
-- host and its history stay; delete the host to drop those too.
CREATE FUNCTION mgmt_remove_remote_target(p_user uuid, p_agent uuid, p_host uuid)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM agent_hosts ah USING hosts h
    WHERE ah.agent_id = p_agent AND ah.host_id = p_host AND ah.mode <> 'local'
      AND h.id = ah.host_id AND h.user_id = p_user;
    RETURN CASE WHEN FOUND THEN 'ok' ELSE 'not_found' END;
END $$;

COMMIT;
