-- P2a container image findings and scores
-- (docs/tasks/phase-2a-image-vulns.md "Matching",
-- docs/decisions/container-image-vulnerabilities.md + follow-up decisions).
--
-- An image's package list (migration 0014) is matched like a host's: its
-- versions are in software_versions, so software_vulnerabilities covers
-- them. On top of that:
--
--   findings kind 'vulnerable_image'  per host, only for images at least
--       one current container on that host uses (any state). One per
--       (host, image, source package, vuln_key),
--       dedup_key = 'img:<image_id>:<source>:<vuln_key>'. Same snapshot
--       and lifecycle columns as 'vulnerable_package', plus the image key
--       and what the UI shows to link back (refs, container names).
--   image_sbom_scores  the score of one package list (worst bucket, counts,
--       max CVSS, KEV), for every image whether used or not. Per list, so
--       it is the same for every user who sees that list;
--       image_scores(user) picks the user's effective list.
--   alert_rules.finding_kinds  which finding kinds a rule's finding.*
--       events select.

BEGIN;

-- Image findings: the image key and a display snapshot, NULL / empty for
-- other kinds. image_refs are the host's repo tags for the image (its repo
-- digests when untagged); container_names the current containers using it.
ALTER TABLE findings
    ADD COLUMN image_id        text,
    ADD COLUMN image_os        text,
    ADD COLUMN image_arch      text,
    ADD COLUMN image_variant   text,
    ADD COLUMN image_refs      text[] NOT NULL DEFAULT '{}',
    ADD COLUMN container_names text[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT findings_image_key_ck CHECK (
        kind <> 'vulnerable_image'
        OR (image_id IS NOT NULL AND image_os IS NOT NULL AND image_arch IS NOT NULL AND image_variant IS NOT NULL));
-- Image detail pages: "which hosts have open findings for image X".
CREATE INDEX findings_image_open_idx ON findings (image_id, severity_key DESC)
    WHERE kind = 'vulnerable_image' AND status = 'open';

-- The score of one package list, written by the worker (store.ScoreImageSBOM)
-- after the list is written and whenever the matches or CVE enrichment of
-- its versions change. Counted per (source package, vuln_key), as findings
-- are, with the same severity.Assess buckets. Kernel binaries in an image
-- are not counted (an image's kernel never runs). No row, or computed_at
-- older than the list's image_sbom_state.updated_at, = not scored yet.
--   not_assessed_count  packages whose ecosystem / distro the matcher does
--                       not cover yet (matcher.Assessed): never "clean"
--   pending_count       versions the matcher had not evaluated when scored
--   matcher_version     matcher.Version at scoring; older rows are
--                       re-scored by image_score_sweep (coverage changes)
CREATE TABLE image_sbom_scores (
    sbom_id             bigint PRIMARY KEY REFERENCES image_sbom_state(id) ON DELETE CASCADE,
    package_count       int NOT NULL,
    not_assessed_count  int NOT NULL,
    pending_count       int NOT NULL DEFAULT 0,
    vuln_count          int NOT NULL,
    critical_count      int NOT NULL DEFAULT 0,
    high_count          int NOT NULL DEFAULT 0,
    medium_count        int NOT NULL DEFAULT 0,
    unknown_count       int NOT NULL DEFAULT 0,
    low_count           int NOT NULL DEFAULT 0,
    negligible_count    int NOT NULL DEFAULT 0,
    worst_severity      text,                   -- NULL = no vulnerabilities
    worst_severity_rank int NOT NULL DEFAULT 0, -- findings.severity_rank scale, 0 = none
    top_severity_key    bigint NOT NULL DEFAULT 0,
    kev_count           int NOT NULL DEFAULT 0,
    fixable_count       int NOT NULL DEFAULT 0, -- fix in the standard channel
    max_cvss            numeric(3,1),
    matcher_version     int NOT NULL,
    computed_at         timestamptz NOT NULL DEFAULT now()
);

-- Per image key as seen by one user: why there is or isn't a list, and
-- the effective list's score. Rows for every container_images key; callers
-- restrict to the user's images (fleet) or one host's (host tabs):
--
--   fleet:  SELECT s.* FROM image_scores($user) s
--           WHERE (s.image_id, s.os, s.arch, s.variant) IN (
--               SELECT hi.image_id, hi.os, hi.arch, hi.variant FROM host_images hi
--               JOIN hosts h ON h.id = hi.host_id
--               WHERE h.user_id = $user AND h.archived_at IS NULL AND hi.removed_at IS NULL)
--   host:   SELECT hi.*, s.* FROM host_images hi
--           LEFT JOIN image_scores($user) s USING (image_id, os, arch, variant)
--           WHERE hi.host_id = $host AND hi.removed_at IS NULL
--
-- Inlined by the planner (a single STABLE SQL SELECT), so those filters
-- drive the lookups. list_status:
--   ok           the effective list (server's, else the user's agent list)
--   unavailable / error   no ok list; list_reason says why (the most
--                recently updated of the server's and the user's rows)
--   none         nothing attempted yet ("no package list yet")
-- scored is false while an ok list has no current score yet; a clean image
-- is list_status 'ok' AND scored AND vuln_count = 0 AND not_assessed_count = 0.
CREATE FUNCTION image_scores(p_user uuid)
RETURNS TABLE (
    image_id text, os text, arch text, variant text,
    list_status text, list_reason text, list_source text, sbom_id bigint,
    distro text, release text, distro_name text,
    scored boolean, scored_at timestamptz,
    package_count int, not_assessed_count int, pending_count int,
    vuln_count int, worst_severity text, worst_severity_rank int, top_severity_key bigint,
    critical_count int, high_count int, medium_count int, unknown_count int,
    low_count int, negligible_count int,
    kev boolean, kev_count int, fixable_count int, max_cvss numeric
)
LANGUAGE sql STABLE AS $$
    SELECT ci.image_id, ci.os, ci.arch, ci.variant,
           CASE WHEN e.sbom_id IS NOT NULL THEN 'ok' ELSE coalesce(f.status, 'none') END,
           CASE WHEN e.sbom_id IS NULL THEN f.reason END,
           e.source, e.sbom_id,
           ok.distro, ok.release, ok.distro_name,
           sc.sbom_id IS NOT NULL AND sc.computed_at >= ok.updated_at, sc.computed_at,
           coalesce(sc.package_count, ok.package_count), sc.not_assessed_count, sc.pending_count,
           sc.vuln_count, sc.worst_severity, sc.worst_severity_rank, sc.top_severity_key,
           sc.critical_count, sc.high_count, sc.medium_count, sc.unknown_count,
           sc.low_count, sc.negligible_count,
           sc.kev_count > 0, sc.kev_count, sc.fixable_count, sc.max_cvss
    FROM container_images ci
    LEFT JOIN image_sbom_effective(p_user) e
           ON e.image_id = ci.image_id AND e.os = ci.os AND e.arch = ci.arch AND e.variant = ci.variant
    LEFT JOIN image_sbom_state ok ON ok.id = e.sbom_id
    LEFT JOIN image_sbom_scores sc ON sc.sbom_id = e.sbom_id
    LEFT JOIN LATERAL (
        SELECT s.status, s.reason FROM image_sbom_state s
        WHERE e.sbom_id IS NULL
          AND s.image_id = ci.image_id AND s.os = ci.os AND s.arch = ci.arch AND s.variant = ci.variant
          AND (s.owner_user_id IS NULL OR s.owner_user_id = p_user)
        ORDER BY s.updated_at DESC, s.id DESC LIMIT 1
    ) f ON true
$$;

-- Finding-kind filter for finding.* events (decided 2026-09-28). An
-- explicit list, not NULL = all: existing rules get both kinds today, and
-- a kind added later is opt-in for existing rules (its migration decides),
-- so no rule starts alerting on something new without the user choosing it.
-- Agent events ignore it.
ALTER TABLE alert_rules
    ADD COLUMN finding_kinds text[] NOT NULL DEFAULT ARRAY['vulnerable_package', 'vulnerable_image'],
    ADD CONSTRAINT alert_rules_finding_kinds_ck CHECK (
        cardinality(finding_kinds) > 0
        AND finding_kinds <@ ARRAY['vulnerable_package', 'vulnerable_image']);

COMMIT;
