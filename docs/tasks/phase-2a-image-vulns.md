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
      `matcher.Assessed` (`web/src/lib/assessed.ts`). Its SQL mirror of
      `severity.Assess` is gone, item below.)
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
- [x] One copy of the ranking rules: have `ScoreImageSBOM` persist the
      per-(source, vuln_key) rows it already assesses, and switch the
      image Vulnerabilities tab to read them instead of the SQL mirror
      of `severity.Assess` (checked equal on real data 2026-09-28: 502
      findings and both image totals). Do before the Phase 2a stack
      merges. (Done 2026-09-29: `image_sbom_vulns`, migration 0018,
      written with the score in `store.ScoreImageSBOM`
      (`imagescore_vulns.go`); the image Vulnerabilities tab and the
      Packages tab's worst severity read it, `web/src/lib/severity-sql.ts`
      deleted; `StaleImageScores` re-scores lists with vulnerabilities
      but no rows, the backfill. On a copy of dev data the rows equal
      the old SQL's output exactly (1021 rows, 6 lists, keys, installed
      versions), per-list totals equal `image_sbom_scores`, and all 290
      open image findings' `severity_key`s match. DOMAIN_MODEL.md §2.6,
      §3.8.)
- [ ] Drop the web mirror of `matcher.Assessed`
      (`web/src/lib/assessed.ts`): persist a per-package "assessed" flag
      (or the not-assessed reason) with the list so the Packages tab and
      list states read Go's answer.
- [x] Image findings on the host Vulnerabilities tab and the fleet
      vulnerability pages (they list only `vulnerable_package` today).
      (Done 2026-09-29, DOMAIN_MODEL.md §3.5, §3.6;
      `web/src/lib/queries-vuln-list.ts`, `web/src/lib/vuln-tables.ts`,
      `web/src/components/vuln/where.tsx`. Host tab and fleet list are
      server-mode DataTables over both kinds with a Where column (host
      package, or image ref + platform + containers linking to the image
      page's Vulnerabilities tab filtered to the CVE) and a Kind facet
      (`?kind=package|image`, none = both); fleet rows are per `vuln_key`
      for host packages and per (`vuln_key`, image key) for images. Fix
      for images: "Rebuild or re-pull image; fixed in X". Counts per
      kind, never summed (cards above the fleet list, lines and two tab
      pills on the host). The CVE page has "Host packages on hosts" and
      "Container images" (image, platform, package, hosts + containers,
      fix). Overview "View all" is unfiltered; host package cards link
      `kind=package`, image numbers `kind=image`; multi-image "Most
      urgent" rows now open the CVE page. Sidebar badge stays host
      packages only. Checked on a copy of dev data: per host and fleet,
      open findings per kind from SQL equal the query results.)
- [x] Server-side Syft for public images without an SBOM attestation:
      pull by digest (the image's platform only) and run Syft as a Go
      library. Bound CPU, memory, disk and concurrency in the worker;
      delete pulled layers after cataloguing. (Done 2026-09-29, no
      migration; ARCHITECTURE.md "Server-side Syft", DOMAIN_MODEL.md
      §4.5. `image_sbom` hands a no-attestation key over to a new
      `image_scan` job (own queue, `SW_IMAGE_SCAN_WORKERS`, default 1)
      without counting an attempt; the sweep also queues the existing
      work-list rows. `internal/imagescan`: our registry client resolves
      the platform manifest (same image-id check) and streams each layer
      by digest through netguard to a temp file (digest + size verified),
      layers are applied into one rootfs through an `os.Root` (no escape
      via names or symlinks, whiteouts + opaque dirs, devices skipped,
      decompressed bytes capped while streaming), then the worker binary
      re-executes itself (`worker syft-catalog`) with GOMAXPROCS /
      GOMEMLIMIT, killed at the deadline, RSS watchdog + Pdeathsig on
      Linux; `sbom.FromEntries` feeds the same purl.Map ->
      WriteImageSBOM -> match/score path with source `server-syft`.
      Bounds: `SW_IMAGE_SCAN_MAX_COMPRESSED_BYTES` 2 GiB,
      `…_MAX_UNCOMPRESSED_BYTES` 8 GiB, `SW_IMAGE_SCAN_TIMEOUT` 20 min,
      `SW_IMAGE_SCAN_CPUS` 1, `SW_IMAGE_SCAN_MEMORY_BYTES` 2 GiB,
      `SW_IMAGE_SCAN_DIR`; `SW_IMAGE_SCAN_ENABLED` and
      `SW_IMAGE_FETCH_ENABLED=false` turn it off. Live on the dev data:
      the 5 no-attestation arm64 images became ok server-syft lists
      (pgadmin4 9.9: 203 packages, 9.18: 196, migrate v4.20.1: 122,
      pgadmin4-docker-extension ×2: 26), scored; `debian:buster`
      amd64 and arm64: 91 packages, identical to the syft v1.52.0 CLI;
      pgadmin4 9.18: 196 purls + 14 purl-less binaries = the CLI's 210.
      Worker binary (linux/arm64, stripped) 13.5 MB -> 77.6 MB.)
- [ ] Server-side Syft follow-ups: run the RSS-watchdog / Pdeathsig path
      in a Linux test (the unit tests run on macOS, where only
      GOMEMLIMIT and the timeout apply); an opaque whiteout doesn't
      empty a lower layer's copy of a directory the same layer merged
      into earlier in its tar (rare ordering); a lock so two worker
      processes can't share `SW_IMAGE_SCAN_DIR` (the start sweep would
      delete the other's scans).
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
- [x] End-of-life base images (e.g. `debian:buster`): show "release out
      of support, not assessed" rather than hiding them or claiming
      clean. (Done 2026-09-29, migration 0019, `matcher.Version` 3;
      DOMAIN_MODEL.md §2.5 "As built", §2.6, §3.8. `matcher.Assessed`
      takes the release's `distro_releases.supported`: a release out of
      support or not listed counts every distro package as not
      assessed, so the image is never clean. 0019 lists Debian 8-10,
      Ubuntu 14.04/16.04/18.04 and the EOL interim releases, Alpine
      3.14-3.18, unsupported with EOL dates. Dashboard: "Release out of
      support" + release + EOL date in score cells, image header and
      note, Packages tab titles, and a count on the Overview. Real data:
      `node:18-buster-slim` (attestation, 318 packages) and
      `debian:bullseye-slim` went from 199 / 0 not assessed (bullseye
      scored clean) to 318 / 96.)
- [ ] Host packages on an end-of-life release have the same gap: a host
      on Debian 10 / 11 gets no findings (no advisories imported) and
      looks clean. Show the host's release support on the host page
      and the Overview.
- [ ] Re-score image lists when a release's `distro_releases.supported`
      flips (today only a `matcher.Version` bump or a list rewrite
      re-scores; a data migration that ends a release's support should
      bump it or clear the affected `image_sbom_scores`).
- [ ] Language ecosystems, one at a time, each with its OSV feed and
      comparator: likely npm, PyPI, Go, then crates.io / Maven. Until an
      ecosystem is added its packages are listed but marked "not
      assessed". npm done 2026-09-29 (`server/internal/npmversion`,
      `osv/language.go`, `matcher.Version` 4; DOMAIN_MODEL.md §2.3, §2.5
      "As built"): OSV `npm` feed (MAL- records skipped), rows under
      ('', 'npm', name), OSV range semantics for language ecosystems,
      GHSA severity as the ranking priority. Live: 7,504 advisories, the
      node images' not-assessed counts 189 → 2 and 318 → 120, 48 npm
      rows in `image_sbom_vulns`. PyPI done 2026-09-29
      (`server/internal/pep440`, equal to pypa/packaging on the feed's
      40,482 versions; `matcher.Version` 5): 13,947 advisories; GHSA and
      PYSEC records for one CVE give one finding.
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
      The `/host` mount is now non-recursive (Phase 1.6), so this needs
      its own binds; see "Agent Syft mounts" below.
- [ ] Agent Syft mounts: the non-recursive `/host` (Phase 1.6) doesn't
      carry `/var/lib/docker` or `/var/lib/containerd` when `/var` is a
      separate filesystem. When agent-side Syft is built, bind both
      read-only under `/host-extra` **only in the Docker opt-in** (the
      compose example's commented socket block and the Register agent
      dialog's Docker checkbox, via `web/src/lib/host-mounts.ts`), with
      `create_host_path: false`, and extend `agent/test/host-mount/run.sh`
      to check that neither directory carries a reachable socket
      (containerd keeps its sockets in `/run`, but check).
- [ ] Verification: compare our results with `docker scout cves` /
      Trivy / Grype on a fixed set of images (`postgres:17`,
      `nginx:1.27`, an Alpine variant, an EOL `debian:buster` image)
      and explain every difference.
