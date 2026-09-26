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

### Phase 1 remainder — vulnerability pipeline (the core value prop)
- [ ] OSV sync worker: pull Debian + Ubuntu ecosystem advisories into
      `vulnerabilities`.
- [ ] dpkg-version-comparison matching (real `dpkg --compare-versions`
      semantics — backport suffixes like `~`, `+deb12u1` must not be
      compared as semver/strings) — see the risk callout in
      DECISIONS.md/README.
- [ ] CISA KEV + FIRST EPSS enrichment, and a severity-ranking function
      that leads with KEV/EPSS, not raw CVSS.
- [ ] Wire matching into the ingest path: the `TODO(phase 1)` in
      `server/internal/ingest/handler.go` currently does nothing after
      insert — enqueue matching per snapshot instead of doing it inline.
- [ ] Findings generation from match results → `findings` table
      (dedup via `dedup_key`, open/resolved lifecycle).
- [ ] Dashboard: findings list/detail page (currently only a count on
      the host list).

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

### Cross-cutting gaps worth closing before real users
- [ ] No automated tests anywhere yet. Highest-value first tests: dpkg
      status parsing, dpkg version comparison (once written), `/proc/net/tcp`
      parsing, and the ingest handler's auth path.
- [ ] No CI pipeline (build/test/lint on push) configured.
- [ ] No agent credential rotation endpoint — only initial enrollment.
- [ ] No host management UI beyond "add" — can't rename, delete, or
      revoke/rotate a host's credentials from the dashboard.
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

## Non-goals (don't build these for MVP)

Auto-patching, remote command execution, compliance reporting
(SOC2/CIS), Windows/macOS support, log analysis/SIEM features. These are
explicit product-scope exclusions, not just "later."
