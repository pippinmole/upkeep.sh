# Done

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
