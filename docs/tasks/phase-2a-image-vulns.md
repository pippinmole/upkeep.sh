# Phase 2a — container image packages + vulnerabilities
Decided 2026-09-28 ([Container image vulnerabilities](../decisions/container-image-vulnerabilities.md)).
Scout-like, on our own pipeline: **inventory first, then matching**, as
for hosts. Every image shows all its packages (OS and language), and
vulnerabilities are a join on top. Package lists come from the server
where it can reach the image (registry SBOM, else pull + Syft) and from
the agent only where it can't; matching and scoring are always
server-side. No external API keys. Order: server-side public images
first (no agent upgrade needed), then more ecosystems, then the agent.
- [x] Migration (done 2026-09-28, migration 0014, DOMAIN_MODEL.md
      §4.5 "Container image packages"; `server/internal/purl`,
      `store/imagesbom.go`): `image_software` (image key as `container_images`:
      image_id, os, arch, variant → `software_versions.id`, plus
      `paths text[]` for where in the image a package was found, which
      matters for language packages) and `image_sbom_state` per image
      key (source `attestation` | `server-syft` | `agent-syft`, tool +
      version, generated_at, status `ok` | `unavailable` | `error` with
      a reason, e.g. "private or local image, waiting for the agent").
      A plain set, not validity ranges: image content is immutable.
      Package URL → `software_versions` mapping: `ecosystem` from the
      purl type, `distro` / `release` from the image's `os-release` for
      distro packages (`''` for language packages), deb source package
      from the purl's `upstream` qualifier where present.
- [x] Worker: `image_sbom` River job, one per image key, enqueued when
      an image key is first seen with a repo digest. Fetch the registry's
      SBOM attestation for the digest (OCI referrers / Docker's
      `attestation-manifest` entries; SPDX and CycloneDX), anonymous
      registry auth, optional platform-wide Docker Hub token for the
      rate limit. Cache per image key fleet-wide; never refetch an `ok`
      one. Timeouts, size caps and `netguard` for outbound fetches.
      (Done 2026-09-28: `internal/registry` (stdlib OCI client),
      `internal/sbom` (SPDX / CycloneDX), `internal/imagesbom`,
      `jobs/imagesbom.go`, queue `images`; DOMAIN_MODEL.md §4.5
      "Container image packages", ARCHITECTURE.md "Container image
      SBOMs". Ingest enqueues a unique `image_sbom` per key in the
      snapshot tx when a `host_images` range opens with a repo digest and
      the key has no server row, or a failed one not on a timer and the
      digest is new; `image_sbom_sweep` every 10 min retries due rows.
      Outcomes: `unavailable` "registry has no SBOM attestation for this
      image" (server-side Syft's work list, `store.SBOMReasonNoAttestation`),
      "private or local image, needs the agent" (401/403/404, private
      address), "image fetching disabled on this server"
      (`SW_IMAGE_FETCH_ENABLED=false`); `error` + backoff 30 min × 2ⁿ,
      capped 24 h, Retry-After respected. The image id must equal the
      index, platform manifest or config digest, so an agent can't attach
      another image's list to a key. Live-checked on Docker Hub:
      postgres:17 → 146 packages (debian 13 / trixie, docker-scout
      1.18.1), postgres:17-alpine → 66 (alpine 3.24).)
- [x] Matching (done 2026-09-28, migration 0015, DOMAIN_MODEL.md §2.6
      "Image findings and scores"; `findings/image.go`,
      `store/imagefindings.go`, `store/imagescore*.go`,
      `jobs/imagefindings.go`): image packages are interned into
      `software_versions`, so the matcher, `software_vulnerabilities`
      and re-match triggers cover them unchanged (nothing in the matcher
      was host-only; the host-only part was the fan-out after a version's
      matches change, now also through `image_software`). Findings per
      host, kind `vulnerable_image`, dedup key
      `img:<image_id>:<source>:<vuln_key>`, only for images a current
      container on the host uses (any state), from the list effective for
      the host's owner; same snapshot, ranking and lifecycle as
      `vulnerable_package`, reconciled in the same `reconcile_host`.
      Triggers: a list written (`EnqueueAfterImageSBOM` ->
      `reconcile_image`), a version's matches changed, a container/image
      range opened or closed at ingest, KEV/EPSS rerank. Every image, used
      or not, gets a score (`image_sbom_scores`, read through
      `image_scores(user)`). Alert rules gained `finding_kinds`.
- [x] Dashboard: image detail page with **Packages** (all of them,
      vulnerable or not, filter by ecosystem, TanStack server-driven
      table) and **Vulnerabilities** tabs; score column on the fleet
      Images page and the host Images / Containers tabs (worst severity
      bucket + counts, max CVSS, KEV flag); explicit states for "no
      package list yet", "private/local image, needs the agent", and
      "ecosystem not assessed".
      (Done 2026-09-28, DOMAIN_MODEL.md §3.8. Route
      `/dashboard/images/-/<image id>?platform=os/arch[/variant]&tab=vulnerabilities`
      (folder `-`; `-` can't start a repository path component,
      so no clash with `[...repo]`); without `platform` the page takes the
      platform on `?host=`, else the first the user has, with a switcher.
      404 unless one of the user's hosts has the image. Header: tags,
      digests, platform, distro/release, list source + tool +
      generated_at, score (counts per bucket, KEV, max CVSS, fixable,
      not assessed), hosts and containers. Both tabs are the first users
      of the DataTable server mode (`useServerTable`, `?q/page/sort/size`
      + facets). Packages: `image_sbom_effective(user)` rows, status
      vulnerable / not assessed / not matched yet / none known, facets
      ecosystem and status. Vulnerabilities: `software_vulnerabilities`
      through the list, grouped per (source package, vuln_key) as
      findings are, so score-only images work; per-row finding lifecycle
      on the user's hosts. States: not inspected on any host, no package
      list yet, local image needs the agent, `unavailable` reasons
      verbatim, error + retry time, release not assessed (EOL / unknown
      distro), matching in progress. Score cells: `ImageScoreCell`.
      Image finding notifications link to the page (`store.ImageFindingURL`).
      Follow-ups: the host Vulnerabilities tab and fleet vulnerability
      pages still list only `vulnerable_package`; the web mirrors
      `severity.Assess` in SQL (`web/src/lib/severity-sql.ts`) and
      `matcher.Assessed` (`web/src/lib/assessed.ts`).)
- [x] Overview page (`/dashboard`) folds in container images, kept apart
      from host packages (never one summed total: an image is fixed by
      rebuilding or re-pulling, a host package by upgrading the host).
      Host cards and bars are labelled "Host packages"; a **Container
      images** section shows vulnerable / scored images, open image
      findings (images, hosts), KEV, severity bars, the 5 most vulnerable
      images in use (score cell, hosts and containers, links to the image
      page) and a "not scored" line (needs the agent / no SBOM / fetch
      failing / waiting). "Most urgent vulnerabilities" ranks both kinds
      and badges each row "Host package" and/or "Image"; an image-only CVE
      in one image links to that image's Vulnerabilities tab filtered to
      it. No Docker data: one line pointing at Images.
      (Done 2026-09-28, DOMAIN_MODEL.md §3.6 "Overview";
      `web/src/lib/queries-overview-images.ts`,
      `web/src/components/overview/`.) Follow-up: the "View all" link and
      the CVE page are still host-package only (item below).
- [ ] One copy of the ranking rules: have `ScoreImageSBOM` persist the
      per-(source, vuln_key) rows it already assesses, and switch the
      image Vulnerabilities tab to read them instead of the SQL mirror
      of `severity.Assess` (checked equal on real data 2026-09-28: 502
      findings and both image totals). Do before the Phase 2a stack
      merges.
- [ ] Image findings on the host Vulnerabilities tab and the fleet
      vulnerability pages (they list only `vulnerable_package` today).
- [ ] Server-side Syft for public images without an SBOM attestation:
      pull by digest (the image's platform only) and run Syft as a Go
      library. Bound CPU, memory, disk and concurrency in the worker;
      delete pulled layers after cataloguing.
- [x] Alpine: OSV `Alpine` ecosystem in `feeds.OSVEcosystems`, apk
      version comparator, `distro_releases` rows. Many official images
      ship `-alpine` variants, so this comes before language packages.
      (Done 2026-09-28, migration 0016; DOMAIN_MODEL.md §2.3, §2.5 "As
      built". `server/internal/apkversion` ports apk-tools' ordering and
      runs its `version.data` vectors; the matcher picks a comparator per
      ecosystem (`matcher.ComparatorFor`, `matcher.Assessed`),
      `matcher.Version` 2. Alpine 3.21-3.24 supported, 3.19/3.20 listed
      as EOL. Live: 3,480 advisories, ~3,100-3,400 affected rows per
      branch. Alpine's feed has **fixed** CVEs only: secdb doesn't track
      unfixed ones, so an Alpine package is never "affected, no fix".)
- [ ] End-of-life base images (e.g. `debian:buster`): show "release out
      of support, not assessed" rather than hiding them or claiming
      clean.
- [ ] Language ecosystems, one at a time, each with its OSV feed and
      comparator: likely npm, PyPI, Go, then crates.io / Maven. Until an
      ecosystem is added its packages are listed but marked "not
      assessed".
- [ ] Agent: package lists for images the server can't pull (no repo
      digest = built locally, or a private registry). The push response
      carries "need a package list for these image IDs"; the agent runs
      Syft over the layers on disk (read-only, the existing `/host`
      mount; both graphdriver overlay2 and the containerd image store,
      whose metadata DB is locked, see [Docker
      collection](../decisions/docker-collection.md) — verify how Syft or we resolve layers there) and
      sends only package URLs + paths, once per image. New wire section
      in PROTOCOL.md; adding it is a privacy decision (the list names
      the software in private images). Weigh the agent binary size cost.
      Keep `/var/lib/docker` / `/var/lib/containerd` readable when the
      `/:/host:ro` mount is narrowed (Phase 1.6), only with Docker on.
- [ ] Verification: compare our results with `docker scout cves` /
      Trivy / Grype on a fixed set of images (`postgres:17`,
      `nginx:1.27`, an Alpine variant, an EOL `debian:buster` image)
      and explain every difference.
