-- Reverses 0023_members: workspace_id columns go back to user_id, and every
-- row is given to one user (the oldest admin, else the oldest user), since
-- the per-user ownership from before 0023 isn't recorded anywhere. Needs at
-- least one user if there is any workspace data.

BEGIN;

DO $$
DECLARE
    owner uuid := (SELECT id FROM users ORDER BY role <> 'admin', created_at, id LIMIT 1);
    r     record;
    def   text;
    has_rows boolean;
BEGIN
    CREATE TEMP TABLE _tenant_tables ON COMMIT DROP AS
    SELECT c.table_name::text AS tbl, c.column_name::text AS col,
           CASE c.column_name WHEN 'workspace_id' THEN 'user_id' ELSE 'owner_user_id' END AS new_col
      FROM information_schema.columns c
     WHERE c.table_schema = 'public'
       AND c.column_name IN ('workspace_id', 'owner_workspace_id');

    CREATE TEMP TABLE _tenant_fks ON COMMIT DROP AS
    SELECT con.conrelid::regclass::text AS tbl, con.conname::text AS name,
           pg_get_constraintdef(con.oid) AS def
      FROM pg_constraint con
      JOIN _tenant_tables t ON t.tbl = con.conrelid::regclass::text
     WHERE con.contype = 'f'
       AND EXISTS (SELECT 1 FROM pg_attribute a
                    WHERE a.attrelid = con.conrelid AND a.attnum = ANY (con.conkey)
                      AND a.attname IN ('workspace_id', 'owner_workspace_id'));
    FOR r IN SELECT * FROM _tenant_fks LOOP
        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', r.tbl, r.name);
    END LOOP;

    FOR r IN SELECT * FROM _tenant_tables LOOP
        EXECUTE format('ALTER TABLE %I RENAME COLUMN %I TO %I', r.tbl, r.col, r.new_col);
        IF owner IS NULL THEN
            EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I WHERE %I IS NOT NULL)', r.tbl, r.new_col)
               INTO has_rows;
            IF has_rows THEN
                RAISE EXCEPTION '0023 down: % has rows but there is no user to own them', r.tbl;
            END IF;
        END IF;
        EXECUTE format('UPDATE %I SET %I = $1 WHERE %I IS NOT NULL', r.tbl, r.new_col, r.new_col) USING owner;
    END LOOP;

    FOR r IN SELECT * FROM _tenant_fks LOOP
        def := regexp_replace(r.def, '\mowner_workspace_id\M', 'owner_user_id', 'g');
        def := regexp_replace(def, '\mworkspace_id\M', 'user_id', 'g');
        def := replace(def, 'REFERENCES workspaces(id)', 'REFERENCES users(id)');
        EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I %s', r.tbl,
                       replace(r.name, 'workspace_id', 'user_id'), def);
    END LOOP;

    FOR r IN
        SELECT con.conrelid::regclass::text AS tbl, con.conname::text AS name
          FROM pg_constraint con
          JOIN _tenant_tables t ON t.tbl = con.conrelid::regclass::text
         WHERE con.conname ~ 'workspace_id'
    LOOP
        EXECUTE format('ALTER TABLE %I RENAME CONSTRAINT %I TO %I', r.tbl, r.name,
                       replace(r.name, 'workspace_id', 'user_id'));
    END LOOP;
    FOR r IN
        SELECT i.indexname::text AS name
          FROM pg_indexes i
          JOIN _tenant_tables t ON t.tbl = i.tablename
         WHERE i.schemaname = 'public' AND i.indexname ~ 'workspace_(id|idx)'
    LOOP
        EXECUTE format('ALTER INDEX %I RENAME TO %I', r.name,
                       replace(replace(r.name, 'workspace_id', 'user_id'), 'workspace_idx', 'user_idx'));
    END LOOP;

    SET LOCAL check_function_bodies = off;
    CREATE TEMP TABLE _tenant_fns ON COMMIT DROP AS
    SELECT p.oid::regprocedure::text AS sig, pg_get_functiondef(p.oid) AS def
      FROM pg_proc p
     WHERE p.pronamespace = 'public'::regnamespace AND p.prokind = 'f'
       AND pg_get_functiondef(p.oid) ~ '\m(p_workspace|workspace_id|owner_workspace_id)\M';
    FOR r IN SELECT * FROM _tenant_fns LOOP
        EXECUTE 'DROP FUNCTION ' || r.sig;
    END LOOP;
    FOR r IN SELECT * FROM _tenant_fns LOOP
        def := regexp_replace(r.def, '\mowner_workspace_id\M', 'owner_user_id', 'g');
        def := regexp_replace(def, '\mworkspace_id\M', 'user_id', 'g');
        def := regexp_replace(def, '\mp_workspace\M', 'p_user', 'g');
        EXECUTE def;
    END LOOP;
END $$;

ALTER TABLE agents DROP COLUMN enrolled_by;
ALTER TABLE enrollment_tokens DROP COLUMN created_by;
ALTER TABLE users
    DROP COLUMN role,
    DROP COLUMN must_change_password,
    DROP COLUMN disabled_at;
DROP TABLE workspaces;

COMMIT;
