-- P1.5 Linux collector breadth (DOMAIN_MODEL.md §4.5 option D, §4.8):
-- services, listeners and local users as validity ranges, on the same
-- pattern as host_software (migration 0003), plus the snapshot scalars the
-- new collectors report.
--
-- Every range table has:
--   row_key   the item's natural key within the host ("systemd/ssh.service",
--             "tcp 0.0.0.0:5432", "alice"): at most one open range per
--             (host, row_key).
--   row_hash  hash of all its reported values (hostfacts.NewSet). Any
--             attribute change (a service stopping, a port changing owner)
--             closes the key's open range and opens a new one, so history
--             shows when it happened.
-- Point-in-time T: first_seen_at <= T AND (removed_at IS NULL OR removed_at > T).
--
-- No backfill: nothing earlier recorded services or users, and TCP
-- listeners stay in listening_sockets (per snapshot) for the history that
-- predates this migration. Ranges start at each host's first push after it.

BEGIN;

-- Per (host, kind) bookkeeping, like host_inventory_state per ecosystem.
-- kind is "<concept>:<scope>": 'services:systemd', 'listeners:tcp',
-- 'listeners:udp', 'users:local'. Each kind is owned by one collector and
-- is only ever diffed when that collector reported ok.
CREATE TABLE host_fact_state (
    host_id               uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    kind                  text NOT NULL,
    -- Hash of the set the open ranges represent. NULL = unknown, e.g. after
    -- a truncated (additive-only) push, which forces the next push to diff.
    set_hash              text,
    -- Range boundary (collected_at, clamped to server time) of the newest
    -- applied set. Pushes not newer than this are stored, not diffed.
    confirmed_at          timestamptz NOT NULL,
    confirmed_snapshot_id uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    -- When a range of this kind last opened or closed.
    changed_at            timestamptz NOT NULL,
    PRIMARY KEY (host_id, kind)
);

-- One table for systemd units, Windows services and launchd jobs
-- (manager). Only systemd is collected today.
CREATE TABLE host_services (
    host_id                uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    manager                text NOT NULL,              -- 'systemd' | 'scm' | 'launchd'
    name                   text NOT NULL,              -- 'ssh.service'
    display_name           text,                       -- systemd Description=
    start_mode             text,                       -- 'auto' | 'manual' | 'disabled' | 'static' | 'masked'
    state                  text,                       -- 'running' | 'stopped'; NULL = unknown
    run_as                 text,                       -- User=, 'root' when unset
    binary_path            text,                       -- first ExecStart= command
    attrs                  jsonb NOT NULL DEFAULT '{}', -- manager extras: unit_path, activated_by, dynamic_user
    row_key                text NOT NULL,
    row_hash               text NOT NULL,
    first_seen_at          timestamptz NOT NULL,
    first_seen_snapshot_id uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    removed_at             timestamptz,
    removed_snapshot_id    uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    PRIMARY KEY (host_id, row_key, first_seen_at),
    CONSTRAINT host_services_range_ck CHECK (removed_at IS NULL OR removed_at > first_seen_at)
);
CREATE UNIQUE INDEX host_services_open_uq ON host_services (host_id, row_key) WHERE removed_at IS NULL;
CREATE INDEX host_services_scope_open_idx ON host_services (host_id, manager) WHERE removed_at IS NULL;

-- Listening sockets as ranges ("port 5432 just started listening on
-- 0.0.0.0" is a range opening). transport partitions the rows between the
-- tcp_listeners and udp_listeners collectors. The owning pid is not stored
-- here (it changes on every restart and would churn ranges); it stays in
-- the per-snapshot listening_sockets rows.
CREATE TABLE host_listeners (
    host_id                uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    transport              text NOT NULL CHECK (transport IN ('tcp', 'udp')),
    proto                  text NOT NULL,              -- 'tcp' | 'tcp6' | 'udp' | 'udp6'
    local_addr             text NOT NULL,
    port                   int  NOT NULL,
    process_name           text,
    row_key                text NOT NULL,
    row_hash               text NOT NULL,
    first_seen_at          timestamptz NOT NULL,
    first_seen_snapshot_id uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    removed_at             timestamptz,
    removed_snapshot_id    uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    PRIMARY KEY (host_id, row_key, first_seen_at),
    CONSTRAINT host_listeners_range_ck CHECK (removed_at IS NULL OR removed_at > first_seen_at)
);
CREATE UNIQUE INDEX host_listeners_open_uq ON host_listeners (host_id, row_key) WHERE removed_at IS NULL;
CREATE INDEX host_listeners_scope_open_idx ON host_listeners (host_id, transport) WHERE removed_at IS NULL;
-- Fleet exposure queries: "which hosts listen on port N".
CREATE INDEX host_listeners_port_open_idx ON host_listeners (port) WHERE removed_at IS NULL;

-- Local accounts from /etc/passwd + /etc/group. Never password hashes.
CREATE TABLE host_users (
    host_id                uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name                   text NOT NULL,
    uid                    bigint NOT NULL,
    gid                    bigint NOT NULL,
    home                   text,
    shell                  text,
    groups                 text[] NOT NULL DEFAULT '{}', -- primary group first
    login_shell            boolean NOT NULL,             -- interactive shell (not nologin/false)
    admin                  boolean NOT NULL,             -- uid 0 or in sudo/wheel/adm/admin
    row_key                text NOT NULL,
    row_hash               text NOT NULL,
    first_seen_at          timestamptz NOT NULL,
    first_seen_snapshot_id uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    removed_at             timestamptz,
    removed_snapshot_id    uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    PRIMARY KEY (host_id, row_key, first_seen_at),
    CONSTRAINT host_users_range_ck CHECK (removed_at IS NULL OR removed_at > first_seen_at)
);
CREATE UNIQUE INDEX host_users_open_uq ON host_users (host_id, row_key) WHERE removed_at IS NULL;

-- Per-push architecture (payload os.arch, Debian naming). hosts.arch (0008)
-- is the current summary from the newest snapshot. snapshots.uptime_seconds
-- and snapshots.facts were reserved by 0008 and are written from now on.
ALTER TABLE snapshots ADD COLUMN arch text;

COMMIT;
