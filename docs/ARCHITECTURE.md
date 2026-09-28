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
  Planned (TASKS.md Phase 1.6): Docker containers, images and Swarm
  services over an opt-in Docker socket mount, through Docker's Go SDK
  behind an interface that only exposes a fixed list of read calls, on
  hosts with their own agent only, not remote (SSH) ones (DECISIONS.md
  "Docker collection").

- **`server/`** — Go, two binaries from one image:
  - `cmd/api`: agent enrollment (`POST /v1/enroll`) and snapshot ingest
    (`POST /v1/snapshots`). Intentionally not a general CRUD API — see
    "Who owns what" below. Holds an insert-only River client: ingest
    enqueues matcher/findings jobs, it never matches inline.
  - `cmd/worker`: background jobs on [River](https://riverqueue.com)
    (Postgres-backed queue, no Redis; DOMAIN_MODEL.md Q10): OSV
    Debian/Ubuntu advisory sync (hourly incremental, weekly full), CISA
    KEV + FIRST EPSS (daily), the vulnerability matcher and findings
    reconciliation (see "Vulnerability pipeline" below), alerting
    (see "Alerting" below), and container image package lists from
    registry SBOM attestations (see "Container image SBOMs" below). Planned: host-side port-exposure
    classification (TASKS.md Phase 1.6; no external scanning, see
    DECISIONS.md "Port exposure"). A
    separate process so multi-minute feed imports (Ubuntu's OSV zip is
    ~800 MB) never compete with ingest. One-shot commands run the same
    code in the foreground: `worker sync osv|kev|epss`, `worker match`
    (sweep + drain), `worker reconcile [host…]`, `worker rerank`,
    `worker image-sbom <image_id> <os> <arch> [variant]`. River
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
| `snapshots`, `listening_sockets`, `host_services`, `host_listeners`, `host_users`, `host_fact_state` | Go (ingest) |
| `agents`, `agent_credentials` | Go (enrollment creates; ingest updates `last_seen_at` / version / platform) |
| `hosts`, `host_identities`, `agent_hosts` | Go (ingest resolves/creates the host on an agent's push, refreshes hostname + OS summary) |
| `software_versions`, `host_software`, `host_inventory_state` | Go (ingest diff) |
| `distro_releases` | migrations (seed); flip `supported` to import a release |
| `advisories`, `advisory_affected`, `advisory_changes`, `cves`, `feed_sync_state` | Go (worker: OSV/KEV/EPSS sync) |
| `software_vulnerabilities`, `software_versions` matcher columns (`match_*`, `kernel_release`, `matcher_version`, `evaluated_at`, `max_fixed_version`) | Go (worker: matcher) |
| `image_sbom_state` (owner NULL), `image_software` of those lists | Go (worker: `image_sbom`) |
| `river_*` | Go (River job queue; API inserts, worker runs) |
| `findings` (kind `vulnerable_package`) | Go (worker: findings reconciliation, re-rank) |
| `alert_events`, `alert_dedup`, `alert_digest_items`, `agent_health`, `alert_rules.last_digest_at` | Go (worker: findings reconcile / agent health write events; alerting jobs the rest) |
| `notifications`, `notification_deliveries`, `notification_delivery_attempts` | Go (worker: alerting), except "Send test": Next.js inserts a `test` notification + delivery and its `alert_deliver` River job |
| `users` | Next.js (signup) |
| `enrollment_tokens` | Next.js (dashboard "Add host") |
| `alert_rules`, `alert_rule_channels`, `notification_channels` | Next.js (Alerts: rules; Settings → Notification settings: channels) |

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

- `users` → `agents` and `hosts` (one user owns many of each; no
  orgs/teams yet, see DECISIONS.md).
- **Agent ≠ host** (migration 0008, DOMAIN_MODEL.md §4): an `agents` row is
  one deployed collector with its own credential (`agent_credentials`,
  1:1, only a secret hash is stored; `agents.revoked_at` refuses it). A
  `hosts` row is one monitored machine; everything below hangs off
  `host_id`. `agent_hosts` assigns hosts to agents with a mode (`local`
  only today; `ssh`/`winrm` reserved), at most one `local` per agent.
  `host_identities` maps stable machine identifiers (`machine_id`) to a
  host, unique per user. Enrollment creates only the agent; ingest creates
  or re-attaches the host on the first push (`store.resolveHost`).
  `hosts` also carries the current OS summary (`os_family`, `os_id`,
  `os_version`, `os_codename`, `kernel`) from the newest snapshot, and
  `duplicate_of` for a possible duplicate identity (Q12).
- `hosts` → `snapshots` (1:many, every historical snapshot kept — not
  upserted — so drift and findings history stay auditable).
  `snapshots.agent_id` records which agent collected it.
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

## Container image SBOMs

TASKS.md Phase 2a, DECISIONS.md "Container image vulnerabilities". The
server's own package list per image key (fleet-wide, `owner_user_id`
NULL) comes from the image's registry SBOM attestation.

```
ingest tx: host_images range opened with a repo digest, key has no server
  row (or a failed one not on a timer, and the digest is new) ──> image_sbom{key}   [images]
every 10 min (fetching enabled) ──> image_sbom_sweep: retry-due rows, keys with a
  repo digest but no server row, rows recorded while fetching was disabled
image_sbom: registry.FetchSBOM ─> sbom.Parse ─> purl.Map ─> WriteImageSBOM
  └─ newly interned versions ──> match_versions (same tx)
```

- `image_sbom` is unique per image key while waiting or running, so the
  fleet enqueues each image once; an `ok` list is never refetched.
- **Outbound fetching** is the one place the server contacts hosts named
  by agents (registries from repo digests), so everything goes through
  `netguard`: public addresses only, checked at dial time, including the
  CDN a registry redirects blob GETs to (https and ports 443/8443 for
  redirect targets; the registry token is dropped on a cross-origin
  redirect). Only GETs by digest; every manifest and blob is verified
  against the digest asked for. Caps: 4 MiB per manifest, 64 MiB per SBOM
  (`SW_IMAGE_MANIFEST_MAX_BYTES`, `SW_IMAGE_SBOM_MAX_BYTES`); 30 s per
  request, 2 min per blob, 10 min per job. Concurrency is the `images`
  queue's worker count (`SW_IMAGE_JOB_WORKERS`, default 2). A 429 backs
  that registry off for the whole process (Retry-After respected,
  default 10 min) and the image is recorded as `error` with a retry,
  never failed permanently.
- Registry auth is anonymous (Bearer token flow, pull scope on the one
  repository). `SW_DOCKERHUB_USERNAME` / `SW_DOCKERHUB_TOKEN` are
  optional platform-wide Docker Hub credentials, sent only to
  `auth.docker.io` for Docker Hub images, only to raise the rate limit
  (anonymous: 100 manifest GETs per hour per IP; an image costs 2 to 3).
- **`SW_IMAGE_FETCH_ENABLED=false`** (default true) turns all outbound
  image fetching off for air-gapped installs: jobs record `unavailable`
  "image fetching disabled on this server" and the sweep isn't
  scheduled. Re-enabling it retries those rows.

## Alerting

Migration 0009. Rules decide *what* to send, channels *where*; channel
types are plugins behind one interface.

```
findings reconcile tx ──> alert_events (outbox) + alert_evaluate (InsertTx)
agent_health (1m)     ──> alert_events on online <-> stale changes
                           (only written when the user has an enabled rule for the type)

alerts queue:
  alert_evaluate  (per trigger + every 1m) advisory-locked; for each pending
                  event x enabled rule of its user: alerting.Match (types,
                  min severity, KEV-only, finding kinds, host scope) -> dedup on
                  (rule, type|subject) within the rule's window ->
                    immediate: one notification per rule per pass
                    digest:    alert_digest_items
                  notification -> one notification_deliveries row per rule
                  channel -> alert_deliver (InsertTx); events marked processed
  alert_digest    (1m) rules whose digest interval elapsed -> one notification
  alert_deliver   Notifier.Send through the channel type's registry entry;
                  each attempt logged; retryable errors back off (30s .. 6h,
                  8 attempts), notify.Permanent errors fail at once
  alert_prune     (1h) events 30d, delivery log 90d
```

- **Finding kinds** (migration 0015): `alert_rules.finding_kinds` selects
  which findings a rule's `finding.*` events cover, `vulnerable_package`
  (host packages) and/or `vulnerable_image` (packages of an image a
  container on the host uses). Never empty; existing and new rules default
  to both. An explicit list rather than NULL = all, so a kind added later
  is opt-in for existing rules (its migration decides). Agent events
  ignore it. Evaluation reads the kind from the event payload
  (`finding.kind`); events without one aren't filtered. Image findings
  use the same `finding.*` events, lifecycle and severity/KEV filters.
- **Never slows ingest**: ingest doesn't touch alerting; the reconcile
  transaction only adds an `INSERT … SELECT` into the outbox, and delivery
  is always a separate job.
- **Notifier interface** (`server/internal/notify`): a channel type
  declares a `Spec` (type key, label, fields; which are secret, which the
  server generates), `Validate(config)` and `Send(ctx, config,
  notification)`. `notify/notifiers.Registry` lists the types. The
  `Notification` / `Event` model is channel-agnostic; its JSON is the
  webhook body ([WEBHOOKS.md](WEBHOOKS.md)).
- **Dashboard forms come from the same declaration**: `go test
  ./internal/notify/notifiers -update` writes
  `web/src/lib/notifier-types.json` (a golden test fails when it is stale);
  the channel dialog renders any type from it, with a per-type override map
  in `web/src/app/dashboard/settings/notifications/channel-forms.tsx` for
  forms that need more.
- **Secrets**: fields declared secret live in `notification_channels.secrets`,
  which dashboard queries never select; generated ones (the webhook
  signing secret) are shown once on create/rotate. They are stored in
  plaintext in Postgres (the worker needs them to sign) — see TASKS.md.
- **Outbound requests** go through `server/internal/netguard` (SSRF guard:
  https, ports 443/8443, public addresses only, checked on the dialed IP,
  same-origin redirects; SMTP connections for the email channel have their
  own port policy, same address checks). `SW_NOTIFY_ALLOW_PRIVATE_NETWORKS=true`
  is a dev-only escape hatch.

### ntfy channel

`server/internal/notify/ntfy` publishes a push notification to a topic on
ntfy.sh or a self-hosted ntfy server. Config: server URL (blank =
`https://ntfy.sh`), topic (ntfy's own rule, `[-_A-Za-z0-9]{1,64}`), an
optional access token (secret field, sent as `Authorization: Bearer …`)
and a priority (Automatic, or a fixed 1–5 that overrides the mapping).

- **Publish**: one JSON `POST` of `{topic, title, message, priority, tags,
  click}` to the server root (a reverse-proxy path prefix is kept), not
  `POST /<topic>` with `X-Title`/`X-Tags` headers: titles and bodies carry
  package, host and agent names verbatim, which JSON encodes safely while
  header values would need RFC 2047 encoding and CR/LF sanitizing.
- **Message**: one event → a title such as `KEV CVE-2024-3094 opened on
  web-1`, `Critical CVE-… reopened on db-1`, `CVE-… resolved on web-1` or
  `Agent "edge" stopped reporting`, and a short plain-text body (package +
  installed version, fix version or "none available yet", severity / KEV /
  EPSS; for agents last seen + hosts), then `Rule: <name>`. Several events
  (a batch or a digest) → the notification's `Summary` as the title and a
  bulleted list of up to 10 events ("…and N more"). Digests are titled
  `Digest: …`. "Send test" sends a fixed test message. The body is kept
  under 3500 bytes (ntfy turns messages over 4 KB into attachments).
- **Priority** (Automatic), highest event wins:

  | Event | Priority |
  |---|---|
  | finding opened/reopened, KEV or critical | 5 urgent |
  | finding opened/reopened, high | 4 high |
  | finding opened/reopened, medium | 3 default |
  | finding opened/reopened, low/negligible/unknown | 2 low |
  | finding resolved, agent recovered | 2 low |
  | agent stale | 4 high |
  | "Send test" | 3 default |

  Digests are capped at 4 (the user chose a roundup over being paged).
  Tags: an emoji for the top event (`rotating_light` KEV/critical,
  `warning` high, `mag` other findings, `white_check_mark` resolved /
  recovered, `electric_plug` stale), plus `kev`, the severity and the
  host name.
- **click**: the event's dashboard link (only when `SW_DASHBOARD_URL` is
  set); for several events, their shared link, else the `/dashboard` root.
- **Errors**: non-2xx fails the attempt with ntfy's error text (its JSON
  `error`, else the truncated body) in the delivery log. 408/425/429/5xx
  are retried with backoff; other 4xx (bad topic, 401/403 token) and 3xx
  fail at once.
- **Ports**: requests go through `netguard` like the webhook, so the
  server must be **public https on port 443 or 8443**. A self-hosted ntfy
  on its default `:80`/`:2586`, on plain http or on a LAN address is
  refused; put it behind a TLS reverse proxy on 443.
  `SW_NOTIFY_ALLOW_PRIVATE_NETWORKS=true` lifts this for local development
  only.

### Email (SMTP) channel

`server/internal/notify/email` sends a plain-text email through the
user's **own SMTP server**. SMTP settings are **per channel**; there is no
platform-wide SMTP config (DECISIONS.md "Email notifier").

- **Fields**: To (required; one or more addresses separated by commas,
  at most 20, each a bare ASCII address), From address (required),
  SMTP server host (required), Port (blank = 587, or 465 when security is
  TLS), Security (select, below), Username (optional), Password (secret
  field; required with a username) and **Allow insecure authentication**
  (checkbox, default off).
- **Security modes**:

  | Mode | Behaviour |
  |---|---|
  | `starttls` (default) | connect in plain text, then STARTTLS; if the server doesn't offer it the delivery fails permanently (never falls back to plain text) |
  | `tls` | implicit TLS from the first byte (usually port 465) |
  | `none` | no TLS at all, for a relay on a trusted network |

  Certificates are always verified (system roots, server name = the host);
  there is no "skip verification" option.
- **Insecure authentication rule**: with the setting off, credentials
  (AUTH PLAIN or LOGIN) are only ever sent over a TLS-protected
  connection. `none` + username + setting off is rejected by `Validate`
  (so "Send test" shows the error) and, as defense in depth, the live
  connection is checked for TLS right before AUTH; either way the delivery
  fails permanently with an error saying to pick STARTTLS/TLS or turn the
  setting on. With the setting on, `none` mode logs in over plain text.
  In `starttls` and `tls` modes the connection is always TLS by the time
  AUTH runs, so the setting makes no difference there. (The package uses
  its own PLAIN/LOGIN implementations: stdlib `smtp.PlainAuth` would
  refuse non-TLS, non-localhost servers on its own terms.)
- **Network**: `netguard.Guard.DialSMTP` — the host must be a DNS name or
  IP literal and the port one of **25, 465, 587, 2525**; every resolved
  address must be public and is checked on the dialed IP, like HTTP. The
  https rules (443/8443) are separate and unchanged. The stdlib `net/smtp`
  client runs over the guarded connection with a 30 s deadline.
  `SW_NOTIFY_ALLOW_PRIVATE_NETWORKS=true` allows any port and private
  addresses for development only. A test SMTP server (Mailpit) and the
  exact channel settings for it are in `dev/smtp/README.md`.
- **Message**: headers `From: "upkeep.sh" <from>`, `To`, `Subject`,
  `Date`, `Message-ID` (`<delivery id@from domain>`, stable across
  retries), `MIME-Version`, `Content-Type: text/plain; charset=utf-8`,
  `Content-Transfer-Encoding: quoted-printable`, `Auto-Submitted:
  auto-generated`, `X-Upkeep-Kind`, `X-Upkeep-Delivery`. Subjects are
  `[upkeep.sh] ` + the same titles as ntfy (`KEV CVE-2024-3094 opened on
  web-1`, `Agent "edge" stopped reporting`, a digest's `Digest: …`
  summary), RFC 2047 encoded when non-ASCII. The body reuses ntfy's text
  (`internal/notify/render`): event detail lines, or a bulleted list of up
  to 50 events, then `Open in upkeep.sh: <link>` (when `SW_DASHBOARD_URL`
  is set) and `Rule: <name>`. "Send test" sends a fixed test message.
- **Header injection**: addresses, host, username and password with CR/LF
  (or other control characters, for addresses and host) are rejected by
  validation; event text in the subject has control characters replaced;
  and the header writer refuses any value containing CR/LF.
- **Errors** (the reply text, on one line and cut to 300 bytes, goes into
  the delivery log):

  | Failure | Handling |
  |---|---|
  | 4xx reply (greylisting, 421 busy, 452 mailbox full, 454 temporary auth failure), connection refused/reset, timeout | retried with backoff |
  | 5xx reply (550 unknown recipient, 535 bad credentials, 554 …) | permanent |
  | STARTTLS required but not offered, no AUTH / no PLAIN or LOGIN offered, insecure-auth refusal | permanent |
  | TLS certificate verification failure, server not speaking TLS in `tls` mode | permanent |
  | destination refused by `netguard` | permanent |

  A rejected recipient aborts the whole message (nobody gets a partial
  send). The SMTP reply code is not stored as the attempt's status code
  (that column is HTTP-only); it is in the error text.

### How to add a notifier (Slack, Discord, …)

1. `server/internal/notify/<type>`: implement `notify.Notifier` (make HTTP
   calls with a `netguard.Guard` client, other protocols through the
   guard's dialers; wrap unfixable errors in `notify.Permanent`).
2. Add it to `notify/notifiers.Registry`.
3. `go test ./internal/notify/notifiers -update` to refresh the dashboard's
   schema file.
4. Only if the generic form can't express it: register a form component in
   `channel-forms.tsx`.

Rules, evaluation, dedup, digests, retries, "Send test" and the delivery
log need no change; `jobs/alerting_integration_test.go` runs the pipeline
with a fake channel type registered next to the webhook to prove it.

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
