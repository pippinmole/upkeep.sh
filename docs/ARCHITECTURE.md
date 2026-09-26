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

- **`server/`** — Go, two binaries from one image:
  - `cmd/api`: agent enrollment (`POST /v1/enroll`) and snapshot ingest
    (`POST /v1/snapshots`). Intentionally not a general CRUD API — see
    "Who owns what" below.
  - `cmd/worker`: background jobs on [River](https://riverqueue.com)
    (Postgres-backed queue, no Redis; DOMAIN_MODEL.md Q10). Today: OSV
    Debian/Ubuntu advisory sync (hourly incremental, weekly full), CISA
    KEV + FIRST EPSS (daily), and the `advisory_rematch` matcher trigger.
    Planned: vulnerability matching, findings reconciliation, port-exposure
    scanning, alert dispatch (see [TASKS.md](TASKS.md)). A separate process
    so multi-minute feed imports (Ubuntu's OSV zip is ~800 MB) never
    compete with ingest; `worker sync osv|kev|epss` runs one sync in the
    foreground. River elects a leader for periodic scheduling and syncs are
    unique jobs, so extra replicas are safe.

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
| `snapshots`, `listening_sockets` | Go (ingest) |
| `software_versions`, `host_software`, `host_inventory_state` | Go (ingest diff) |
| `distro_releases` | migrations (seed); flip `supported` to import a release |
| `advisories`, `advisory_affected`, `advisory_changes`, `cves`, `feed_sync_state` | Go (worker: OSV/KEV/EPSS sync) |
| `software_vulnerabilities` | Go (matcher — not yet built) |
| `river_*` | Go (River job queue, worker process) |
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

See `migrations/` for the authoritative schema. Summary:

- `users` → `hosts` (one user owns many hosts; no orgs/teams yet, see
  DECISIONS.md).
- `hosts` → `agent_credentials` (1:1, only a secret hash is stored) and
  `snapshots` (1:many, every historical snapshot kept — not upserted —
  so drift and findings history stay auditable).
- `snapshots` → `listening_sockets` (facts for that push). `snapshots.collector_status` records each collector's outcome.
- Package inventory history: `software_versions` (fleet-wide interned
  versions, keyed by `ecosystem`) and `host_software` (per-host validity
  ranges, `removed_at IS NULL` = current). Ingest diffs each push against
  the open ranges per ecosystem, skipping the diff when the set hash in
  `host_inventory_state` is unchanged (DOMAIN_MODEL.md §2.2). The
  legacy per-push copy, `snapshot_packages`, was dropped in migration
  0004 (DOMAIN_MODEL.md Q6).
- Advisories (DOMAIN_MODEL.md §2.4, migration 0005): `advisories` (one
  row per OSV record: DSA/DLA/DEBIAN-CVE, USN/LSN/UBUNTU-CVE, keyed
  downstream by `vuln_key`), `advisory_affected` (per release codename +
  source package + channel: fixed version or NULL = unfixed, distro
  severity; `channel = 'ubuntu-pro'` marks ESM/Pro-only rows), only for
  `distro_releases.supported` releases. `advisory_changes` is the matcher's
  durable dirty set of (distro, release, source package). `cves` holds
  per-CVE KEV/EPSS/CVSS. `feed_sync_state` holds cursors/ETags/stats per
  feed. `software_vulnerabilities` (positive matches per interned version)
  is filled by the matcher.
- River's tables (`river_job`, `river_leader`, `river_queue`, ...) are
  vendored as migration 0006 from `river migrate-get`, so golang-migrate
  owns the whole schema.
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
