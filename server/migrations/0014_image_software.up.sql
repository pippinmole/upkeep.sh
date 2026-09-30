-- P2a container image packages (docs/tasks/phase-2a-image-vulns.md,
-- docs/decisions/container-image-vulnerabilities.md): the package list of
-- an image, interned into software_versions like host packages, so the
-- matcher,
-- software_vulnerabilities and every re-match trigger cover images
-- unchanged.
--
-- An image's content never changes, so its package list is a plain set per
-- image key (image_id, os, arch, variant, as in container_images), not
-- validity ranges. A list is only ever replaced as a whole (a better source
-- or tool re-generates it); see store.WriteImageSBOM.
--
-- Trust scoping (decided 2026-09-28): a list the server obtained itself, by
-- digest ('attestation', 'server-syft'), is fleet-wide (owner NULL). A list
-- sent by an agent ('agent-syft') is stored per user (owner = users.id) and
-- used only for that user's hosts, so one user's agent can't clean or
-- poison another user's results. A server list that is ok wins over an
-- agent list for the same image key (image_sbom_effective below).
--
-- No backfill: nothing earlier stored image packages.

BEGIN;

-- One row per (image key, owner): the list's provenance, plus the attempt
-- bookkeeping of whoever produces it (the server's image_sbom worker for
-- owner NULL; the agent round trip for a user's row). No row = nothing
-- attempted yet ("no package list yet").
--
-- Owner modelling: owner_user_id is NULL for the fleet-wide server list.
-- The key is enforced by one UNIQUE NULLS NOT DISTINCT constraint (Postgres
-- 15+), so NULL counts as one owner and ON CONFLICT works for both kinds
-- with the same target; no sentinel user, no pair of partial indexes. A
-- surrogate id keys the package rows instead of repeating the nullable
-- five-column key in image_software (the big table stays narrow, and
-- replacing or deleting a list is by one id).
CREATE TABLE image_sbom_state (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    image_id        text NOT NULL,
    os              text NOT NULL,
    arch            text NOT NULL,
    variant         text NOT NULL,
    owner_user_id   uuid REFERENCES users(id) ON DELETE CASCADE, -- NULL = server-obtained, fleet-wide
    status          text NOT NULL,              -- ok | unavailable | error
    -- Why there is no list: shown as is ("private or local image, waiting
    -- for the agent", "registry returned 429"). NULL when ok.
    reason          text,
    -- Provenance of the list; NULL until one is stored. A failed attempt
    -- never overwrites an ok row (the list stays), so in practice these
    -- are set exactly when status = 'ok'.
    source          text,                       -- attestation | server-syft | agent-syft
    tool_name       text,                       -- SBOM generator ('syft', 'buildkit-syft-scanner', ...)
    tool_version    text,
    generated_at    timestamptz,                -- when the SBOM was generated (from the document), else when stored
    package_count   int,                        -- rows in image_software for this list
    -- The image's OS from the SBOM's os-release (NULL = none found, e.g.
    -- distroless or scratch). release is the key its distro packages were
    -- interned under (software_versions.release: the codename for
    -- debian/ubuntu, major.minor for alpine; purl.ReleaseFor), so the UI
    -- and later matching can say which release it is.
    distro          text,                       -- os-release ID: 'debian', 'ubuntu', 'alpine'
    distro_version  text,                       -- os-release VERSION_ID: '12', '22.04', '3.20.3'
    release         text,                       -- 'bookworm', 'jammy', '3.20'
    distro_name     text,                       -- os-release PRETTY_NAME, for display
    -- Attempt bookkeeping. attempts counts failed attempts since the last
    -- success (0 when ok); next_attempt_at is when the producer may try
    -- again, NULL = don't retry on a timer (ok, or waiting for something
    -- else to change, e.g. the agent to send a list). Transient failures
    -- inside one job are River's retries and aren't recorded here.
    attempts        int NOT NULL DEFAULT 0,
    last_attempt_at timestamptz,
    next_attempt_at timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT image_sbom_state_key UNIQUE NULLS NOT DISTINCT (image_id, os, arch, variant, owner_user_id),
    CONSTRAINT image_sbom_state_image_fk FOREIGN KEY (image_id, os, arch, variant)
        REFERENCES container_images (image_id, os, arch, variant) ON DELETE CASCADE,
    CONSTRAINT image_sbom_state_status_ck CHECK (status IN ('ok', 'unavailable', 'error')),
    CONSTRAINT image_sbom_state_ok_ck CHECK (
        status <> 'ok' OR (source IS NOT NULL AND generated_at IS NOT NULL AND reason IS NULL)),
    CONSTRAINT image_sbom_state_reason_ck CHECK (status = 'ok' OR reason IS NOT NULL),
    -- Server sources are fleet-wide, agent lists are per user.
    CONSTRAINT image_sbom_state_source_ck CHECK (
        source IS NULL
        OR (source IN ('attestation', 'server-syft') AND owner_user_id IS NULL)
        OR (source = 'agent-syft' AND owner_user_id IS NOT NULL))
);
-- The image_sbom worker's retry scan.
CREATE INDEX image_sbom_state_retry_idx ON image_sbom_state (next_attempt_at)
    WHERE next_attempt_at IS NOT NULL;
-- A user's agent lists (and ON DELETE CASCADE from users).
CREATE INDEX image_sbom_state_owner_idx ON image_sbom_state (owner_user_id)
    WHERE owner_user_id IS NOT NULL;

-- The package set of one list: which interned versions an image contains
-- and where. Rows exist only while their list is ok. paths: locations in
-- the image the package was found at (dpkg status file, a
-- package-lock.json, a Go binary, ...), which matters for language
-- packages; several SBOM entries with the same interned key are merged
-- into one row with the union of their paths.
CREATE TABLE image_software (
    sbom_id     bigint NOT NULL REFERENCES image_sbom_state(id) ON DELETE CASCADE,
    software_id bigint NOT NULL REFERENCES software_versions(id),
    paths       text[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (sbom_id, software_id)          -- packages of an image
);
-- Reverse lookup: which images contain version X (reconcile image findings
-- when a version's matches change).
CREATE INDEX image_software_software_idx ON image_software (software_id, sbom_id);

-- The effective package list of every image key as seen by one user: the
-- server list if it is ok, else that user's agent list if it is ok. Image
-- keys with neither are absent. Inlined by the planner, so filters on the
-- image key push down into it:
--
--   SELECT sv.*, isw.paths
--   FROM image_sbom_effective($user) e
--   JOIN image_software isw ON isw.sbom_id = e.sbom_id
--   JOIN software_versions sv ON sv.id = isw.software_id
--   WHERE (e.image_id, e.os, e.arch, e.variant) = ($1, $2, $3, $4);
--
-- Why a list is missing (no row, unavailable, error) is read from
-- image_sbom_state directly, for both the server row and the user's.
CREATE FUNCTION image_sbom_effective(p_user uuid)
RETURNS TABLE (sbom_id bigint, image_id text, os text, arch text, variant text,
               owner_user_id uuid, source text, distro text, release text)
LANGUAGE sql STABLE AS $$
    SELECT DISTINCT ON (s.image_id, s.os, s.arch, s.variant)
           s.id, s.image_id, s.os, s.arch, s.variant, s.owner_user_id, s.source, s.distro, s.release
    FROM image_sbom_state s
    WHERE s.status = 'ok' AND (s.owner_user_id IS NULL OR s.owner_user_id = p_user)
    ORDER BY s.image_id, s.os, s.arch, s.variant, s.owner_user_id NULLS FIRST
$$;

COMMIT;
