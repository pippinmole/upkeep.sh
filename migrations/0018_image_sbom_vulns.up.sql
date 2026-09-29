-- P2a: one copy of the ranking rules (docs/tasks/phase-2a-image-vulns.md,
-- DOMAIN_MODEL.md §2.6 "Image findings and scores", §3.8).
--
-- The per-(source package, vuln_key) groups of one package list, as
-- store.ScoreImageSBOM assessed them (findings.BuildImage grouping,
-- severity.Assess buckets and keys): what image_sbom_scores counts, row by
-- row. The image detail page's Vulnerabilities tab (and the Packages
-- tab's worst severity) read these instead of re-deriving severity in
-- SQL. Written in the same transaction as the list's image_sbom_scores
-- row and replaced as a whole; current only while that score is
-- (computed_at >= image_sbom_state.updated_at), readers check that.
--
-- The representative row of a group (installed / fixed version, fix
-- channel, distro severity, ecosystem) is its lowest installed source
-- version by the ecosystem's comparator, as for findings. is_kev,
-- epss_score and cvss_v3_score are the cves enrichment the severity was
-- assessed with (a change re-scores the list, findings_rerank).
--
-- Existing scores have no rows: image_score_sweep (StaleImageScores)
-- re-scores a list whose score counts vulnerabilities but which has no
-- rows here, so they fill in on the first sweep after deploy.

BEGIN;

CREATE TABLE image_sbom_vulns (
    sbom_id           bigint NOT NULL REFERENCES image_sbom_state(id) ON DELETE CASCADE,
    source_package    text NOT NULL,
    vuln_key          text NOT NULL,
    ecosystem         text NOT NULL,
    installed_version text NOT NULL,
    fixed_version     text,
    fix_channel       text CHECK (fix_channel IN ('standard', 'ubuntu-pro')),
    fix_advisory_id   text,
    advisory_ids      text[] NOT NULL DEFAULT '{}',
    distro_severity   text,
    packages          text[] NOT NULL DEFAULT '{}', -- binary names in the group
    software_ids      bigint[] NOT NULL DEFAULT '{}', -- their software_versions ids
    severity          text NOT NULL,                -- severity.Bucket name
    severity_rank     int NOT NULL,                 -- findings.severity_rank scale
    severity_key      bigint NOT NULL,              -- findings.severity_key
    is_kev            boolean NOT NULL DEFAULT false,
    epss_score        numeric(6,5),
    cvss_v3_score     numeric(3,1),
    PRIMARY KEY (sbom_id, source_package, vuln_key)
);

COMMIT;
