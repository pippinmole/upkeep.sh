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
    "Who owns what" below. Holds an insert-only River client: ingest
    enqueues matcher/findings jobs, it never matches inline.
  - `cmd/worker`: background jobs on [River](https://riverqueue.com)
    (Postgres-backed queue, no Redis; DOMAIN_MODEL.md Q10): OSV
    Debian/Ubuntu advisory sync (hourly incremental, weekly full), CISA
    KEV + FIRST EPSS (daily), the vulnerability matcher and findings
    reconciliation (see "Vulnerability pipeline" below). Planned:
    port-exposure scanning, alert dispatch (see [TASKS.md](TASKS.md)). A
    separate process so multi-minute feed imports (Ubuntu's OSV zip is
    ~800 MB) never compete with ingest. One-shot commands run the same
    code in the foreground: `worker sync osv|kev|epss`, `worker match`
    (sweep + drain), `worker reconcile [host…]`, `worker rerank`. River
    elects a leader for periodic scheduling, syncs are unique jobs and
    matcher writes take a Postgres advisory lock, so extra replicas are
    safe.

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
| `software_vulnerabilities`, `software_versions` matcher columns (`match_*`, `kernel_release`, `matcher_version`, `evaluated_at`, `max_fixed_version`) | Go (worker: matcher) |
| `river_*` | Go (River job queue; API inserts, worker runs) |
| `findings` (kind `vulnerable_package`) | Go (worker: findings reconciliation, re-rank) |
| `alert_events` | Go (alerting worker — not yet built) |
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
  `vulnerable_package` findings are one per (host, source package,
  vuln_key), `dedup_key = pkg:<source>:<vuln_key>`, reconciled from
  `software_vulnerabilities` (migration 0007).

## Vulnerability pipeline

Matching is per interned package version, not per host or per push
(DOMAIN_MODEL.md §2.6): `software_vulnerabilities` holds the positive
matches of each `software_versions` row, computed in Go
(`internal/matcher`, dpkg ordering from `internal/debversion`), and
per-host `findings` are reconciled from it.

```
agent push ──> api: InsertSnapshot tx ──┬─ match_versions{ids}   (new / source-reset versions)
                                         └─ reconcile_host{host}  (ranges changed, or running kernel changed)
                 (River InsertTx: jobs commit iff the snapshot does)

OSV sync ── advisory_affected + advisory_changes (same tx) ──> advisory_rematch
worker start, every 5m ──> matcher_sweep, advisory_rematch     (safety net / initial run / version bump)

matcher queue (serialized by pg_advisory_xact_lock):
  match_versions     evaluate the given versions
  matcher_sweep      evaluate versions with matcher_version NULL or < matcher.Version
  advisory_rematch   drain advisory_changes: re-evaluate versions with that
                     (distro, release, match_source); delete the key iff its
                     changed_at is unchanged
      └─ versions whose match set changed ──> reconcile_host for each host having them

findings queue:
  reconcile_host     host lock; snooze while any installed version is unevaluated;
                     build desired findings (running-kernel policy), open / keep /
                     reopen / resolve
  findings_rerank    after KEV / EPSS / OSV syncs that changed cves rows:
                     recompute severity of open findings for those CVEs
```

- Every evaluation takes the matcher advisory lock *before* reading
  advisories, so evaluations of one version can't commit out of order.
- `reconcile_host` never runs against unevaluated versions (it snoozes),
  so an upgrade never resolves findings the pending match job would
  reopen.
- Kernel CVEs are raised only for the running kernel
  (`snapshots.kernel_release`); other installed kernels are exposed by the
  `host_kernel_packages` view (DOMAIN_MODEL.md Q7).
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
