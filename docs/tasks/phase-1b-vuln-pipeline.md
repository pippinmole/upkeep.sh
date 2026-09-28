# Phase 1 remainder — vulnerability pipeline (P1b, the core value prop)
Design: [DOMAIN_MODEL.md §2.3–2.6](../DOMAIN_MODEL.md#23-advisory-source).
Matching is server-side against the stored inventory (not per snapshot),
so new advisories apply retroactively to current *and* historical
inventories.
- [x] `server/internal/debversion`: real `dpkg --compare-versions`
      semantics in Go (epochs, `~` sorts before end-of-string, digit/
      non-digit runs) — backport suffixes like `~deb11u1`, `+deb12u1`,
      `ubuntu0.22.04.1`, `+esm1` must not be compared as semver/strings.
      Test against dpkg's own vectors. Postgres never compares versions.
- [x] Migration `0005_advisories`: replaces `vulnerabilities` with
      `distro_releases` (seeded, `supported` flag), `advisories`,
      `advisory_affected` (per release + source package + `channel`
      standard|ubuntu-pro), `advisory_changes` (matcher dirty set), `cves`,
      `feed_sync_state`, `software_vulnerabilities` (empty).
      `findings.vulnerability_id` → `findings.vuln_key text`.
- [x] OSV sync worker (`server/cmd/worker`, `internal/osv`,
      `internal/feeds`): Debian + Ubuntu top-level `all.zip` (per-release
      zips are stale since 2024-10); hourly incremental via
      `modified_id.csv` + ETag; full import weekly, on first run, or when
      the supported set changes; changes recorded per (distro, release,
      source) in `advisory_changes`.
- [x] CISA KEV + FIRST EPSS daily sync into `cves` (KEV falls back to
      CISA's GitHub `cisagov/kev-data` when cisa.gov returns 403).
- [x] Postgres-backed job queue: River v0.47 (Q10 resolved), tables
      vendored as migration `0006_river_queue`, separate worker process.
- [ ] Faster full OSV sync: skip full parse of zip entries whose
      `modified` matches the stored value (Ubuntu full import is
      CPU-bound, ~3 min native / ~17 min in Docker Desktop).
- [x] Matcher (`internal/matcher`, `store/matching.go`, migration 0007):
      each `software_versions` row evaluated once against
      `advisory_affected` for its (distro, release, source) with
      `debversion` → `software_vulnerabilities` (replaced only when the
      match set changes; CVE-keyed, per-CVE record authoritative, Pro
      channel labelled). Triggers: `match_versions` enqueued by ingest via
      an insert-only River client (`InsertTx`); `advisory_rematch` drains
      `advisory_changes`; `matcher_sweep` (start + every 5m) covers
      never/stale-evaluated rows and `matcher.Version` bumps.
- [x] Replace the `TODO(phase 1)` in `server/internal/ingest/handler.go`:
      ingest enqueues `match_versions` / `reconcile_host` in the snapshot
      transaction; nothing is matched inline. (The port-exposure half of
      that TODO remains, as `TODO(phase 1, exposure)`.)
- [x] Findings reconciliation (`internal/findings`, `store/findings.go`)
      → `findings` per (host, source package, vuln),
      `dedup_key = pkg:<source>:<vuln_key>`, open / resolved / reopened
      lifecycle; runs only when a host's inventory or running kernel
      changed, or a version it has changed matches. Severity via
      `severity.Assess`; `findings_rerank` after KEV/EPSS/OSV syncs.
- [x] Severity-ranking function (single tested Go func): KEV, then EPSS,
      then distro priority/urgency, CVSS only as tiebreaker; "no fix yet"
      kept visible, not hidden.
- [x] Kernel source-name mapping (Ubuntu `linux-signed-*`/`linux-meta-*`/
      `linux-restricted-modules-*`, Debian `linux-signed-<arch>` → advisory
      `linux*` sources) + running-vs-installed policy (Q7 resolved: agent
      `os.kernel` collector, `snapshots.kernel_release`, findings for the
      running kernel only, `host_kernel_packages` view for the rest).
- [ ] Report Ubuntu Pro attachment from the agent
      (`/var/lib/ubuntu-advantage/status.json`) so attached hosts can show
      "fix available via Pro" instead of "requires Pro" (Q9 follow-up;
      the label is correct without it).
- [x] Alert hooks on finding transitions (opened / reopened / resolved
      from `reconcile_host`): written to the `alert_events` outbox in the
      reconcile transaction, `alert_evaluate` queued with `InsertTx`
      (migration 0009, ARCHITECTURE.md "Alerting").
