-- Members and roles (docs/MEMBERS.md): one shared workspace per install,
-- and a role on every user.
--
-- Before this migration every row of user-facing data (hosts, agents,
-- enrollment tokens, notification channels, alert rules, report schedules,
-- swarm clusters, agent-sent image SBOMs, ...) was owned by one user through
-- a user_id column, so each user saw only their own. From here on that data
-- belongs to a workspace: every user_id column (and image_sbom_state.
-- owner_user_id) becomes workspace_id (owner_workspace_id), referencing the
-- new workspaces table. An install has exactly one workspace, created here;
-- the dashboard resolves it (web/src/lib/viewer.ts) and every signed-in user
-- reads it. Roles on users gate writes; the database doesn't know about
-- roles beyond storing them.
--
-- Why a workspace_id column instead of dropping the scoping altogether: the
-- rename keeps every query's shape and parameters (only the value passed
-- changes, from the user's id to the workspace's), keeps the composite
-- tenant foreign keys (a rule can't point at another tenant's channel), and
-- keeps the Go integration tests' per-test tenants. Nothing here stops a
-- second workspace later; the app just never creates one.
--
-- The column/constraint work below is generic (every public table with a
-- user_id column except Better Auth's sessions and accounts), so tables
-- added by migrations numbered before this one are converted too. The
-- mgmt_* and image_* functions are rewritten the same way.
--
-- Existing data: the oldest user becomes an admin, everyone else a member,
-- and every user's rows move into the one workspace. Rows that collide once
-- tenants merge (the same machine-id identity, swarm cluster id or agent
-- SBOM claimed by two users) keep the oldest one; the others are deleted
-- and are re-created by the next agent push. Nothing is deployed yet, so
-- this is acceptable (docs/MEMBERS.md, "Tenancy migration").

BEGIN;

CREATE TABLE workspaces (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL DEFAULT 'Default workspace',
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO workspaces (name) VALUES ('Default workspace');

-- Roles. 'admin' = full access; 'member' = read-only. The first user to
-- sign up on a fresh install becomes admin (web/src/lib/auth.ts); here the
-- oldest existing user does.
-- must_change_password: set when an admin creates the account or resets its
-- password (a temporary password), cleared when the user picks their own.
-- disabled_at: set = cannot sign in; sessions are deleted when it is set.
ALTER TABLE users
    ADD COLUMN role                 text        NOT NULL DEFAULT 'member'
        CONSTRAINT users_role_ck CHECK (role IN ('admin', 'member')),
    ADD COLUMN must_change_password boolean     NOT NULL DEFAULT false,
    ADD COLUMN disabled_at          timestamptz;
UPDATE users SET role = 'admin'
 WHERE id = (SELECT id FROM users ORDER BY created_at, id LIMIT 1);

-- Who issued a token and who enrolled an agent (the token's issuer, copied
-- at enrollment since the token row is deleted then). Audit only: removing
-- the user keeps the token and the agent.
ALTER TABLE enrollment_tokens
    ADD COLUMN created_by uuid REFERENCES users(id) ON DELETE SET NULL;
UPDATE enrollment_tokens SET created_by = user_id;
ALTER TABLE agents
    ADD COLUMN enrolled_by uuid REFERENCES users(id) ON DELETE SET NULL;
UPDATE agents SET enrolled_by = user_id;

-- Rows whose natural key includes the tenant and would collide once every
-- user's rows share one tenant: keep the oldest.
DELETE FROM host_identities hi
 USING host_identities k
 WHERE hi.kind = k.kind AND hi.value = k.value AND hi.user_id <> k.user_id
   AND (k.created_at, k.host_id) < (hi.created_at, hi.host_id);
DELETE FROM swarm_clusters sc -- cascades to swarm_services
 USING swarm_clusters k
 WHERE sc.cluster_id = k.cluster_id AND sc.user_id <> k.user_id
   AND (k.first_seen_at, k.user_id) < (sc.first_seen_at, sc.user_id);
DELETE FROM image_sbom_state s
 USING image_sbom_state k
 WHERE s.owner_user_id IS NOT NULL AND k.owner_user_id IS NOT NULL
   AND s.owner_user_id <> k.owner_user_id
   AND (s.image_id, s.os, s.arch, s.variant) IS NOT DISTINCT FROM (k.image_id, k.os, k.arch, k.variant)
   AND k.id < s.id;

DO $$
DECLARE
    ws  uuid := (SELECT id FROM workspaces);
    r   record;
    def text;
BEGIN
    -- The tables to convert: every public table with a user_id column except
    -- Better Auth's, plus image_sbom_state (owner_user_id).
    CREATE TEMP TABLE _tenant_tables ON COMMIT DROP AS
    SELECT c.table_name::text AS tbl, c.column_name::text AS col,
           CASE c.column_name WHEN 'user_id' THEN 'workspace_id' ELSE 'owner_workspace_id' END AS new_col
      FROM information_schema.columns c
     WHERE c.table_schema = 'public'
       AND c.column_name IN ('user_id', 'owner_user_id')
       AND c.table_name NOT IN ('sessions', 'accounts');

    -- 1. Drop every foreign key that involves a tenant column (to users, and
    --    the composite (x_id, user_id) ones between tenant tables), saving
    --    the definitions.
    CREATE TEMP TABLE _tenant_fks ON COMMIT DROP AS
    SELECT con.conrelid::regclass::text AS tbl, con.conname::text AS name,
           pg_get_constraintdef(con.oid) AS def
      FROM pg_constraint con
      JOIN _tenant_tables t ON t.tbl = con.conrelid::regclass::text
     WHERE con.contype = 'f'
       AND EXISTS (SELECT 1 FROM pg_attribute a
                    WHERE a.attrelid = con.conrelid AND a.attnum = ANY (con.conkey)
                      AND a.attname IN ('user_id', 'owner_user_id'));
    FOR r IN SELECT * FROM _tenant_fks LOOP
        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', r.tbl, r.name);
    END LOOP;

    -- 2. Rename the columns and point every row at the workspace.
    FOR r IN SELECT * FROM _tenant_tables LOOP
        EXECUTE format('ALTER TABLE %I RENAME COLUMN %I TO %I', r.tbl, r.col, r.new_col);
        EXECUTE format('UPDATE %I SET %I = $1 WHERE %I IS NOT NULL', r.tbl, r.new_col, r.new_col) USING ws;
    END LOOP;

    -- 3. Re-create the foreign keys on the renamed columns; the ones to
    --    users now reference workspaces.
    FOR r IN SELECT * FROM _tenant_fks LOOP
        def := regexp_replace(r.def, '\mowner_user_id\M', 'owner_workspace_id', 'g');
        def := regexp_replace(def, '\muser_id\M', 'workspace_id', 'g');
        def := replace(def, 'REFERENCES users(id)', 'REFERENCES workspaces(id)');
        EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I %s', r.tbl,
                       replace(r.name, 'user_id', 'workspace_id'), def);
    END LOOP;

    -- 4. Rename the remaining constraints (primary keys, uniques, not-nulls)
    --    and indexes whose names mention the old column.
    FOR r IN
        SELECT con.conrelid::regclass::text AS tbl, con.conname::text AS name
          FROM pg_constraint con
          JOIN _tenant_tables t ON t.tbl = con.conrelid::regclass::text
         WHERE con.conname ~ 'user_id'
    LOOP
        EXECUTE format('ALTER TABLE %I RENAME CONSTRAINT %I TO %I', r.tbl, r.name,
                       replace(r.name, 'user_id', 'workspace_id'));
    END LOOP;
    FOR r IN
        SELECT i.indexname::text AS name
          FROM pg_indexes i
          JOIN _tenant_tables t ON t.tbl = i.tablename
         WHERE i.schemaname = 'public' AND i.indexname ~ 'user_(id|idx)'
    LOOP
        EXECUTE format('ALTER INDEX %I RENAME TO %I', r.name,
                       replace(replace(r.name, 'user_id', 'workspace_id'), 'user_idx', 'workspace_idx'));
    END LOOP;

    -- 5. Rewrite the SQL functions that scope by tenant (mgmt_*, the
    --    image_sbom_effective/image_scores readers): p_user becomes
    --    p_workspace and the columns follow the rename. Dropped and
    --    re-created because a parameter or output column can't be renamed
    --    in place; bodies aren't checked until every one exists again.
    SET LOCAL check_function_bodies = off;
    CREATE TEMP TABLE _tenant_fns ON COMMIT DROP AS
    SELECT p.oid::regprocedure::text AS sig, pg_get_functiondef(p.oid) AS def
      FROM pg_proc p
     WHERE p.pronamespace = 'public'::regnamespace AND p.prokind = 'f'
       AND pg_get_functiondef(p.oid) ~ '\m(p_user|user_id|owner_user_id)\M';
    FOR r IN SELECT * FROM _tenant_fns LOOP
        EXECUTE 'DROP FUNCTION ' || r.sig;
    END LOOP;
    FOR r IN SELECT * FROM _tenant_fns LOOP
        def := regexp_replace(r.def, '\mowner_user_id\M', 'owner_workspace_id', 'g');
        def := regexp_replace(def, '\muser_id\M', 'workspace_id', 'g');
        def := regexp_replace(def, '\mp_user\M', 'p_workspace', 'g');
        EXECUTE def;
    END LOOP;

    IF EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'public' AND column_name IN ('user_id', 'owner_user_id')
                  AND table_name NOT IN ('sessions', 'accounts')) THEN
        RAISE EXCEPTION '0023: a tenant column was left unconverted';
    END IF;
END $$;

COMMIT;
