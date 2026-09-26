# Architecture

## Components

```
┌──────────────┐   HTTPS push only    ┌──────────────────┐
│    Agent     │ ───────────────────> │   Go ingest API   │
│  (Go binary, │   (no inbound ports)  │  (server/cmd/api) │
│  per host)   │                       └─────────┬─────────┘
└──────────────┘                                  │ writes
                                                   v
┌──────────────┐   direct reads +   ┌──────────────────┐
│   Next.js    │ ─── simple writes ─> │    Postgres       │
│  dashboard   │   (Server Actions)   │                    │
└──────────────┘                       └──────────────────┘
```

- **`agent/`** — single static Go binary, MIT/Apache-licensed, distributed
  as a Docker image (see `agent/docker-compose.example.yml`) or a plain
  systemd unit. Runs with `pid: host` + `network_mode: host` (to see the
  real host's processes/sockets, not the container's own) and a read-only
  `/:/host:ro` bind mount (for filesystem facts native namespaces don't
  expose: dpkg database, `/etc/os-release`, reboot-required flag). It
  collects facts only — no command execution, no inbound ports. CVE
  matching happens server-side so the agent stays small and auditable.

- **`server/`** — Go. Today: agent enrollment (`POST /v1/enroll`) and
  snapshot ingest (`POST /v1/snapshots`). Planned: background workers for
  OSV/KEV/EPSS sync, vulnerability matching, external port-exposure
  scanning, and alert dispatch (see [TASKS.md](TASKS.md)). This is
  intentionally not a general CRUD API — see "Who owns what" below.

- **`web/`** — Next.js (App Router) on Bun. Marketing page, Auth.js
  credentials auth (self-hosted, bcrypt, own `users` table), and the
  dashboard. Deployed as a standalone Docker image (`output: "standalone"`
  in `next.config.ts`) since this is self-hosted via Dokploy, not Vercel.

- **`migrations/`** — SQL migrations (golang-migrate `.up.sql`/`.down.sql`
  pairs). This is the actual contract between `server/` and `web/`, since
  both read/write the same Postgres schema directly.

## Who owns what (avoiding split-brain writes)

Two codebases touch the same schema. Ownership is drawn by **who needs to
enforce business logic on a table**, not by "which language talks to the
DB" — see [DECISIONS.md](DECISIONS.md#direct-postgres-reads-from-nextjs)
for the reasoning.

| Table | Written by |
|---|---|
| `snapshots`, `snapshot_packages`, `listening_sockets` | Go (ingest) |
| `vulnerabilities` | Go (OSV/KEV/EPSS sync worker — not yet built) |
| `findings`, `alert_events` | Go (matching/alerting workers — not yet built) |
| `users` | Next.js (signup) |
| `enrollment_tokens` | Next.js (dashboard "Add host") |
| `alert_rules`, `notification_channels` | Next.js (settings — not yet built) |

Both sides **read** any table directly from Postgres. There is no caching
layer in front of these reads today — every dashboard render is a live
query. If caching is added later (e.g. Next.js `"use cache"` +
`cacheTag`), the tables Go writes to must be invalidated by Go calling an
on-demand revalidation endpoint in Next.js after it writes — the standard
pattern for an external writer invalidating Next.js's cache (same shape
as a CMS webhook), not a workaround. See DECISIONS.md for the full
reasoning trail on this.

## Data model

See `migrations/0001_init.up.sql` for the authoritative schema. Summary:

- `users` → `hosts` (one user owns many hosts; no orgs/teams yet, see
  DECISIONS.md).
- `hosts` → `agent_credentials` (1:1, only a secret hash is stored) and
  `snapshots` (1:many, every historical snapshot kept — not upserted —
  so drift and findings history stay auditable).
- `snapshots` → `snapshot_packages`, `listening_sockets` (facts for that
  push).
- `vulnerabilities` — cached CVE data synced from OSV (Debian/Ubuntu
  ecosystems), enriched with CISA KEV and FIRST EPSS.
- `hosts` → `findings` (kind: `vulnerable_package` | `public_port` |
  `reboot_required`; deduplicated via `dedup_key`, tracked open/resolved).
- `users` → `alert_rules` → `notification_channels`, and
  `findings` → `alert_events` (delivery log, dedup, digest support).

## Protocol

See [PROTOCOL.md](PROTOCOL.md) for the full agent↔server wire format and
versioning policy.

## Deployment shapes

- **Local dev**: `docker-compose.dev.yml` — hardcoded dev credentials, no
  `.env` needed, zero-setup.
- **Production (the platform itself)**: `docker-compose.yml`, deployed
  once on your own box via Dokploy, reading a root `.env`
  (`.env.example` is the template).
- **Monitored hosts**: `agent/docker-compose.example.yml`, deployed once
  per host you want monitored, pointed at the platform's public API URL
  with a one-time enrollment token from the dashboard.
