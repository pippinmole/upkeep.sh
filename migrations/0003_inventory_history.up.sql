-- P1a: package inventory history as validity ranges (DOMAIN_MODEL.md §2.2,
-- §2.6), plus per-snapshot collector status (§4.5) and a backfill from the
-- legacy per-snapshot copies in snapshot_packages.
--
-- Everything is keyed by `ecosystem` ('deb' today; later rpm, apk,
-- windows-program, homebrew, ...), never by dpkg specifics.

BEGIN;

-- §3.7: every dashboard query is scoped by hosts.user_id.
CREATE INDEX IF NOT EXISTS hosts_user_id_idx ON hosts(user_id);

-- collector_status: the payload's `collectors` map verbatim; NULL for
-- agents that predate it. package_set_hashes: {"<ecosystem>": "<sha256>"}
-- for each ecosystem that was authoritative in this push; NULL when none
-- was (or for snapshots written before this migration).
ALTER TABLE snapshots
    ADD COLUMN collector_status   jsonb,
    ADD COLUMN package_set_hashes jsonb;

-- Fleet-wide interned package versions. Immutable except that an inferred
-- source (older agents / backfill send none) is replaced by a real one the
-- first time any agent reports it; matcher bookkeeping is then reset.
--
-- The unique key is (ecosystem, distro, release, name, version, arch).
-- Source is deliberately an attribute, not part of the key: in one distro
-- release a binary version has exactly one source in the archive, and
-- keying on it would split history (close + reopen every range) the day a
-- host's agent starts sending real source names.
CREATE TABLE software_versions (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ecosystem         text NOT NULL,            -- 'deb'; later 'rpm','apk','homebrew','windows-program',...
    distro            text NOT NULL DEFAULT '', -- os.id for distro-scoped ecosystems ('ubuntu','debian'), else ''
    release           text NOT NULL DEFAULT '', -- os.codename for distro-scoped ecosystems, else ''
    name              text NOT NULL,            -- binary package / program / app name
    version           text NOT NULL,
    arch              text NOT NULL DEFAULT '',
    source_name       text,                     -- deb: source package (advisories key on it)
    source_version    text,
    source_inferred   boolean NOT NULL DEFAULT false, -- true: source defaulted to the binary name/version
    attrs             jsonb NOT NULL DEFAULT '{}',    -- ecosystem-specific extras (publisher, bundle id, ...)
    -- matching bookkeeping, written by the P1b matcher
    matcher_version   int,                      -- NULL = never evaluated
    evaluated_at      timestamptz,
    max_fixed_version text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT software_versions_key UNIQUE (ecosystem, distro, release, name, version, arch)
);
CREATE INDEX software_versions_source_idx ON software_versions (ecosystem, distro, release, source_name);
CREATE INDEX software_versions_name_idx   ON software_versions (name text_pattern_ops);

-- Per-host inventory history. A row is "software_id was installed on
-- host_id from first_seen_at until removed_at" (NULL = still installed as
-- of the host's last successful inventory for that ecosystem). The same
-- software_id may have several non-overlapping ranges (reinstalls).
-- Point-in-time T: first_seen_at <= T AND (removed_at IS NULL OR removed_at > T).
CREATE TABLE host_software (
    host_id                uuid   NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    software_id            bigint NOT NULL REFERENCES software_versions(id),
    first_seen_at          timestamptz NOT NULL,
    first_seen_snapshot_id uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    removed_at             timestamptz,
    removed_snapshot_id    uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    PRIMARY KEY (host_id, software_id, first_seen_at),
    CONSTRAINT host_software_range_ck CHECK (removed_at IS NULL OR removed_at > first_seen_at)
);
-- Current inventory of a host; also enforces one open range per version.
CREATE UNIQUE INDEX host_software_open_uq ON host_software (host_id, software_id) WHERE removed_at IS NULL;
-- "Which hosts currently have version X" (fleet views, findings reconcile).
CREATE INDEX host_software_open_by_software_idx ON host_software (software_id) WHERE removed_at IS NULL;
-- History tab: changes per host, newest first.
CREATE INDEX host_software_opened_idx  ON host_software (host_id, first_seen_at DESC);
CREATE INDEX host_software_removed_idx ON host_software (host_id, removed_at DESC) WHERE removed_at IS NOT NULL;

-- Per (host, ecosystem) inventory bookkeeping. Replaces the single
-- hosts.current_package_set_hash sketched in DOMAIN_MODEL.md §2.2: package
-- sources succeed or fail independently, so each needs its own hash and its
-- own "last confirmed" time.
CREATE TABLE host_inventory_state (
    host_id               uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    ecosystem             text NOT NULL,
    -- Hash of the set the open ranges represent. NULL = unknown (e.g. after
    -- the backfill), which forces the next push to run a full diff.
    package_set_hash      text,
    -- Range boundary (collected_at, clamped to server time) of the newest
    -- applied inventory. Pushes not newer than this are stored, not diffed.
    confirmed_at          timestamptz NOT NULL,
    confirmed_snapshot_id uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    -- When a range for this ecosystem last opened or closed.
    changed_at            timestamptz NOT NULL,
    PRIMARY KEY (host_id, ecosystem)
);

-- ---------------------------------------------------------------------
-- Backfill from snapshot_packages.
--
-- Mirrors the Go ingest rules for pre-collectors payloads (ingest.planInventory):
-- a legacy snapshot is authoritative for 'deb' only if it has at least one
-- package row and a non-empty os_id; source is inferred as the binary
-- name/version; snapshots are applied in collected_at order and one not
-- strictly newer than the previous applied one is skipped (ties: earliest
-- received wins). Ranges are computed set-based (gaps and islands) rather
-- than by row-by-row replay: an island of consecutive authoritative
-- snapshots containing a version becomes one range, closed at the next
-- authoritative snapshot that lacks it.
--
-- Idempotent: hosts that already have a 'deb' host_inventory_state row are
-- skipped, and interning is ON CONFLICT DO NOTHING, so re-running this
-- block changes nothing.
-- ---------------------------------------------------------------------

CREATE TEMP TABLE bf_snap AS
WITH candidates AS (
    SELECT s.id, s.host_id, s.collected_at, s.received_at,
           s.os_id AS distro, COALESCE(s.os_codename, '') AS release
    FROM snapshots s
    WHERE s.os_id <> ''
      AND EXISTS (SELECT 1 FROM snapshot_packages sp WHERE sp.snapshot_id = s.id)
      AND NOT EXISTS (SELECT 1 FROM host_inventory_state st
                      WHERE st.host_id = s.host_id AND st.ecosystem = 'deb')
), ordered AS (
    SELECT DISTINCT ON (host_id, collected_at) *
    FROM candidates
    ORDER BY host_id, collected_at, received_at, id
)
SELECT *, row_number() OVER (PARTITION BY host_id ORDER BY collected_at) AS seq
FROM ordered;
CREATE UNIQUE INDEX ON bf_snap (host_id, seq);

INSERT INTO software_versions
    (ecosystem, distro, release, name, version, arch, source_name, source_version, source_inferred)
SELECT DISTINCT 'deb', b.distro, b.release, sp.name, sp.version, sp.arch, sp.name, sp.version, true
FROM bf_snap b
JOIN snapshot_packages sp ON sp.snapshot_id = b.id
ON CONFLICT ON CONSTRAINT software_versions_key DO NOTHING;

INSERT INTO host_software
    (host_id, software_id, first_seen_at, first_seen_snapshot_id, removed_at, removed_snapshot_id)
SELECT i.host_id, i.software_id, f.collected_at, f.id, n.collected_at, n.id
FROM (
    SELECT host_id, software_id, min(seq) AS first_seq, max(seq) AS last_seq
    FROM (
        SELECT b.host_id, sv.id AS software_id, b.seq,
               b.seq - row_number() OVER (PARTITION BY b.host_id, sv.id ORDER BY b.seq) AS island
        FROM bf_snap b
        JOIN snapshot_packages sp ON sp.snapshot_id = b.id
        JOIN software_versions sv
          ON sv.ecosystem = 'deb' AND sv.distro = b.distro AND sv.release = b.release
         AND sv.name = sp.name AND sv.version = sp.version AND sv.arch = sp.arch
    ) presence
    GROUP BY host_id, software_id, island
) i
JOIN bf_snap f      ON f.host_id = i.host_id AND f.seq = i.first_seq
LEFT JOIN bf_snap n ON n.host_id = i.host_id AND n.seq = i.last_seq + 1;

-- package_set_hash stays NULL: the Go hash is not reproduced in SQL, so the
-- first push after this migration runs one full diff against these ranges
-- (a no-op for ranges when nothing changed; it also upgrades the inferred
-- sources on the interned rows).
INSERT INTO host_inventory_state
    (host_id, ecosystem, package_set_hash, confirmed_at, confirmed_snapshot_id, changed_at)
SELECT DISTINCT ON (b.host_id)
       b.host_id, 'deb', NULL, b.collected_at, b.id,
       COALESCE((SELECT max(GREATEST(hs.first_seen_at, COALESCE(hs.removed_at, hs.first_seen_at)))
                 FROM host_software hs WHERE hs.host_id = b.host_id), b.collected_at)
FROM bf_snap b
ORDER BY b.host_id, b.seq DESC;

DROP TABLE bf_snap;

COMMIT;
