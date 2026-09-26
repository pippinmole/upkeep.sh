# Tasks

Status as of 2026-09-26. Check this before starting new work — it's the
single source of truth for what's done vs. outstanding, kept ahead of
memory or a stale conversation summary.

## Done

**Agent** (`agent/`)
- [x] Fact collectors: dpkg installed packages (`internal/collector/packages.go`),
      OS release (`osrelease.go`), listening TCP sockets via native `/proc`
      with pid→process mapping (`ports.go`), reboot-required flag
      (`reboot.go`).
- [x] Enrollment (one-time token → persisted `agent_id`/`agent_secret`)
      and periodic snapshot push over HTTPS (`internal/transport`,
      `cmd/agent`).
- [x] Dockerfile (scratch-based static binary) +
      `docker-compose.example.yml` for one-click deploy on a monitored
      host.

**Server** (`server/`)
- [x] `POST /v1/enroll`, `POST /v1/snapshots`, `GET /healthz`
      (`internal/ingest/handler.go`).
- [x] Postgres store via pgx (`internal/store`) — enrollment token
      consumption, host creation, agent secret storage/verification,
      snapshot + packages + sockets insert (single transaction, `COPY`
      for bulk rows).
- [x] Secret hashing (SHA-256, constant-time compare) — `internal/authn`.
- [x] Dockerfile.

**Database**
- [x] Initial schema (`migrations/0001_init.up.sql` / `.down.sql`): users,
      hosts, enrollment_tokens, agent_credentials, snapshots,
      snapshot_packages, listening_sockets, vulnerabilities, findings,
      alert_rules, notification_channels, alert_events.

**Web** (`web/`)
- [x] Next.js 16 App Router + Bun + Tailwind + oxlint/oxfmt.
- [x] Auth.js credentials auth (signup + login), `proxy.ts` route
      protection for `/dashboard/*`.
- [x] Dashboard: host list with last-seen + open-finding counts (direct
      Postgres read, `lib/queries.ts`), "Add host" flow that issues an
      enrollment token and renders a ready-to-paste `docker run` command.
- [x] Standalone Docker build (`output: "standalone"`, multi-stage
      Dockerfile, Bun for build, plain Node for runtime).

**Infra / tooling**
- [x] `docker-compose.dev.yml` (local, zero-setup) and `docker-compose.yml`
      (production/Dokploy, reads root `.env`).
- [x] Root `.env.example` + gitignored `.env` with generated dev secrets.
- [x] Version audit pass: Go 1.27.1, Node 24-alpine, Postgres 18.6-alpine,
      golang-migrate v4.20.1, all npm/bun deps verified current.
- [x] Postgres 18 data-mount fix (`pgdata:/var/lib/postgresql`, not the
      old `/var/lib/postgresql/data` path).

## To do

Roughly in the order they unblock each other. See root `README.md` for
the original phased roadmap; this list is the actionable breakdown.
[DOMAIN_MODEL.md](DOMAIN_MODEL.md) holds the design behind the P1a–c and
Phase 1.5 items below, including open questions (Q1–Q16) to settle
before or while building them.

### Phase 1 remainder — package inventory history (P1a)
Design: [DOMAIN_MODEL.md §2.2](DOMAIN_MODEL.md#22-storage-model-for-inventory-history).
The agent already sends the full dpkg inventory every push; what's missing
is a history model that doesn't copy ~1,500 rows per snapshot.
- [x] Agent: send `source` / `source_version` per package from dpkg's
      `Source:` field (`Source: foo` and `Source: foo (1.2-3)` forms;
      absent → same as binary). Additive, stays `schema_version: 1`.
- [x] Agent: fix the installed-state check in `parseDpkgStatus` —
      `strings.Contains(status, "installed")` also matches
      `half-installed` / `not-installed`; test the third word of
      `Status:` instead.
- [x] Agent: also count `triggers-pending` / `triggers-awaited` as
      installed (files on disk, only a trigger outstanding), so a push
      landing mid-`apt` doesn't record false remove/re-add history.
- [x] Migration `0003_inventory_history`: `software_versions`
      (fleet-wide interned, key `(ecosystem, distro, release, name,
      version, arch)`) + `host_software` validity ranges, per-(host,
      ecosystem) `host_inventory_state` (set hash + last confirmed; replaces
      the single `hosts.current_package_set_hash`),
      `snapshots.package_set_hashes` + `snapshots.collector_status`,
      `hosts(user_id)` index.
- [x] Ingest: per-ecosystem diff against open ranges in the snapshot
      transaction, host row locked; skipped entirely when the set hash is
      unchanged; never closes ranges for an ecosystem whose collector isn't
      `ok` or when `packages` is null/missing (rules for old agents in
      PROTOCOL.md). `server/internal/inventory` + `ingest/inventory.go`.
- [x] Backfill `host_software` by replaying existing `snapshot_packages`
      in order (set-based SQL in migration 0003, idempotent).
- [x] Stop writing `snapshot_packages` and drop it (migration
      `0004_drop_snapshot_packages`; DOMAIN_MODEL.md Q6 resolved: retire).
- [x] Fix `store.InsertSnapshot` hardcoding `schema_version = 1` instead
      of using the payload's value.
- [ ] Agent-clock robustness: range boundaries use `collected_at`
      (clamped to server time). A host clock that jumps *backwards* makes
      pushes look stale (stored, not diffed) until it catches up; consider
      falling back to `received_at` when that happens.

### Phase 1 remainder — vulnerability pipeline (P1b, the core value prop)
Design: [DOMAIN_MODEL.md §2.3–2.6](DOMAIN_MODEL.md#23-advisory-source).
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
- [ ] Alert hooks on finding transitions (opened / reopened / resolved
      from `reconcile_host`) — with the alerting worker.

### Phase 1 remainder — packages & vulnerabilities UI (P1c)
Design: [DOMAIN_MODEL.md §3](DOMAIN_MODEL.md#3-packages-in-the-dashboard).
Direct Postgres reads from Server Components, filters in URL search
params, no new Go endpoints.
- [x] Host detail shell `/dashboard/hosts/[hostId]` (header: OS, last
      seen, reboot pill, collector-health alerts; link tabs).
- [ ] Host header vuln/KEV pills (data ready: open `findings`).
- [x] Packages tab: searchable/filterable per-host inventory,
      installed-since, `?at=<date>` point-in-time view.
- [ ] Packages tab P1b columns: installed vs fixed version, status, top
      severity; row sheet with the package's CVEs.
- [ ] Vulnerabilities tab (replaces the old "findings list/detail page"
      item — currently only a count on the host list), with resolved
      history toggle.
- [x] History tab: installed/removed/"changed" per range boundary, paired
      on read by (ecosystem, name, arch).
- [ ] History tab: upgraded vs downgraded (via `debversion`) and "fixed N
      CVEs" per change (backed by a derived `host_software_changes` table
      written by ingest).
- [ ] Fleet `/dashboard/vulnerabilities` + `/dashboard/vulnerabilities/[vulnKey]`
      (affected hosts, "previously affected" from inventory history).
- [x] Fleet `/dashboard/packages` + `/dashboard/packages/[name]` ("which
      hosts have package X, at which versions", previously installed).
- [ ] Overview page stat cards (currently a placeholder).
- [x] shadcn components: `select`, `pagination` (host tabs are link tabs,
      so `tabs` wasn't needed).
- [ ] Index `host_software (software_id) WHERE removed_at IS NOT NULL`
      for "previously installed/affected" fleet queries.
- [ ] 24 pre-existing files fail `oxfmt --check` (ui/*, nav-*, providers).

### Phase 1 remainder — exposure + alerting
- [ ] External port-exposure scanner: scan only an IP verified as an
      enrolled agent's own connection source (`snapshots.source_ip`),
      rate-limited, platform must never be usable to scan arbitrary
      targets.
- [ ] `listening_sockets.is_public` currently always `false` (column
      exists, nothing sets it yet) — populate from the scan result.
- [ ] Alert rule evaluation worker + dispatch: webhook (HMAC-signed),
      email, Discord, Slack, ntfy. Dedup + digest mode
      (`alert_rules.digest`).
- [ ] Dashboard: alert rule + notification channel CRUD (currently no
      UI at all — schema exists, nothing writes to it yet).

### Phase 1.5 — agent/host split + Linux collector breadth
Design: [DOMAIN_MODEL.md §4](DOMAIN_MODEL.md#4-domain-model-agents-hosts-os-families).
Today agent == host: enrollment creates a `hosts` row and the returned
`agent_id` *is* `hosts.id`. Independent of P1a–c (new tables key on
`host_id`, which survives the split).
- [ ] Migration: `agents`, re-key `agent_credentials` to `agent_id`,
      `agent_hosts` (mode `local`/`ssh`/`winrm`, one local per agent),
      `host_identities`, `hosts.os_family` + current OS summary columns,
      `snapshots.agent_id`/`facts`/`uptime_seconds` (`collector_status`
      already landed in P1a).
      Backfill with `agents.id = hosts.id` so deployed agents'
      `credentials.json` keeps working unchanged.
- [ ] Enrollment creates an agent, not a host; host upserted on first push
      by identity (`/etc/machine-id`), so an agent reinstall reattaches to
      the existing host instead of duplicating it. Duplicate-identity
      flagging (open question Q12).
- [ ] Payload `schema_version: 2`: `agent` + `host` blocks (ref,
      identity, hostname refreshed every push, `os_family`) and
      per-collector status; v1 payloads keep mapping to the agent's local
      host.
- [ ] Dashboard: rename the current "Agents" host list to **Hosts**; new
      **Agents** page lists collectors (version, platform, last seen,
      hosts collected, revoke).
- [ ] Linux collectors: uptime, hostname + machine-id (running kernel
      landed in P1b as `os.kernel`),
      UDP listeners, systemd services (unit files + `/proc/*/cgroup`, no
      D-Bus), local users (`/etc/passwd`/`/etc/group`), processes on
      deleted libraries (`/proc/*/maps`), unattended-upgrades config +
      last apt update.
- [ ] `host_services` / `host_listeners` on the same validity-range
      pattern as `host_software`.
- [ ] Remote collection (SSH/WinRM from a subnet agent) — **blocked on
      open questions Q3–Q5** (command execution principle, credential
      storage, port-scan eligibility). Schema supports it; don't build
      until decided.

### Cross-cutting gaps worth closing before real users
- [ ] Tests: dpkg status parsing, OS detection and the inventory range
      diff / set hash / old-agent rules now have tests (server store tests
      need `SW_TEST_DATABASE_URL`, otherwise skipped). Still missing: dpkg
      version comparison (once written), `/proc/net/tcp` parsing, and the
      ingest handler's auth path.
- [ ] No CI pipeline (build/test/lint on push) configured.
- [ ] No agent credential rotation endpoint — only initial enrollment.
- [ ] No host management UI beyond "add" — can't rename, delete, or
      revoke/rotate a host's credentials from the dashboard. (After the
      Phase 1.5 split, credentials belong to agents: revoke/rotate lives
      on the Agents page, rename/archive/merge on Hosts.)
- [ ] `agent/docker-compose.example.yml` references
      `ghcr.io/icondesk/security-whatnot-agent:latest`, which doesn't
      exist yet — needs a build/publish pipeline before that snippet is
      actually usable end-to-end.
- [ ] No expired-enrollment-token cleanup job (minor — they're just dead
      rows, not a security issue since they're checked against
      `expires_at`).
- [ ] `server/Dockerfile` runtime base (`alpine:3.20`) wasn't covered by
      the last version audit — check it.

### Phase 2+ (explicitly deferred, don't start early)
- [ ] Container image vulnerability scanning for Docker workloads.
- [ ] RHEL/Alpine package collectors (agent currently Debian/Ubuntu-only
      by design).
- [ ] SMS notifications.
- [ ] Billing/Stripe (see DECISIONS.md — deferred until real users).
- [ ] Multi-tenant orgs/teams (see DECISIONS.md — deferred until demand).
- [ ] Cache layer + revalidation webhook for dashboard reads (only
      needed if a specific page is actually slow — see DECISIONS.md).

### Phase 3/4 — Windows and macOS agents (pending scope decision)
**Not started, and currently contradicts the non-goals below** — see
DOMAIN_MODEL.md open question Q1. Per-OS collector lists are in
[DOMAIN_MODEL.md §4.8](DOMAIN_MODEL.md#48-per-os-collectors-whats-worth-sampling)
and the support matrix in §5.
- [ ] Decide Q1 (in scope? which first?) and update the non-goals below,
      README, and ARCHITECTURE.md accordingly.
- [ ] Windows agent (native service): OS build/UBR, installed programs,
      KBs, Windows Update state, pending reboot, SCM services, listeners,
      Defender/firewall/BitLocker. Vuln matching approach: Q14.
- [ ] macOS agent (launchd daemon, signed pkg): SystemVersion, apps +
      pkgutil receipts, Homebrew, launchd services, SoftwareUpdate state,
      XProtect/ALF/FileVault. Vuln matching approach: Q14.

## Non-goals (don't build these for MVP)

Auto-patching, remote command execution, compliance reporting
(SOC2/CIS), Windows/macOS support, log analysis/SIEM features. These are
explicit product-scope exclusions, not just "later."

> Note (2026-09-26): Windows/macOS support and agent-initiated remote
> collection are under reconsideration in
> [DOMAIN_MODEL.md](DOMAIN_MODEL.md) (open questions Q1, Q3). Until those
> are decided, this list stands. "Remote command execution" here means
> the *server* causing execution on a host, and stays excluded either
> way.
