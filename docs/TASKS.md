# Tasks

Status as of 2026-09-27. Check this before starting new work — it's the
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
Phase 1.5 items below, including open questions (Q1–Q17) to settle
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
- [x] Alert hooks on finding transitions (opened / reopened / resolved
      from `reconcile_host`): written to the `alert_events` outbox in the
      reconcile transaction, `alert_evaluate` queued with `InsertTx`
      (migration 0009, ARCHITECTURE.md "Alerting").

### Phase 1 remainder — packages & vulnerabilities UI (P1c)
Design: [DOMAIN_MODEL.md §3](DOMAIN_MODEL.md#3-packages-in-the-dashboard).
Direct Postgres reads from Server Components, filters in URL search
params, no new Go endpoints.
- [x] Host detail shell `/dashboard/hosts/[hostId]` (header: OS, last
      seen, reboot pill, collector-health alerts; link tabs).
- [x] Host header vuln/KEV pills (open count, top severity, KEV count)
      and running kernel (`snapshots.kernel_release`, "unknown" shown
      explicitly); same pills on the host list rows.
- [x] Packages tab: searchable/filterable per-host inventory,
      installed-since, `?at=<date>` point-in-time view.
- [x] Packages tab P1b columns: status (open findings via
      `host_package_vuln_status`; non-running kernels labelled info), top
      severity/KEV, "fixed in" (`max_fixed_version`); vulnerability filter,
      most-urgent-first default sort; `?pkg=` row sheet with the package's
      CVEs. Under `?at=` the counts are that version's matches against
      today's advisories.
- [x] Vulnerabilities tab `/dashboard/hosts/[hostId]/vulnerabilities`:
      open findings most urgent first, open/resolved toggle, severity/KEV/
      fix filters, `?v=` detail sheet (CVE + advisories), running-kernel
      panel from `host_kernel_packages`.
- [x] History tab: installed/removed/"changed" per range boundary, paired
      on read by (ecosystem, name, arch).
- [x] History tab: upgraded vs downgraded (deb, via a TS port of dpkg
      ordering in `web/src/lib/debversion.ts`, checked against the Go
      package's 806 dpkg vectors) and "fixed N / introduced N" per change
      (set difference of `software_vulnerabilities`, today's advisory
      data), computed on read.
- [ ] Move the FilterBar tables (host packages / vulnerabilities / history,
      fleet packages / vulnerabilities) to `DataTable` in server mode
      (`web/src/components/data-table/`, `tableStateFromParams` +
      `useServerTable`); the SQL side keeps its allowlisted sort keys and
      bound params (DOMAIN_MODEL Q11).
- [ ] `host_software_changes` derived table written by ingest (pairing +
      direction once in Go) — only if the on-read History tab gets slow.
- [x] Fleet `/dashboard/vulnerabilities` (open / "resolved everywhere",
      filters, sorts) + `/dashboard/vulnerabilities/[vulnKey]` (CVE
      facts, affected hosts, affected versions on your hosts, previously
      affected = resolved findings, per-release fixes, advisories).
- [ ] "Previously affected" from inventory ranges (hosts that had a
      vulnerable version before findings existed); today it is resolved
      findings only.
- [ ] Automated test for `web/src/lib/debversion.ts` against
      `server/internal/debversion/testdata/dpkg_compare_vectors.txt`
      (checked by hand; web/ has no test runner yet).
- [x] Fleet `/dashboard/packages` + `/dashboard/packages/[name]` ("which
      hosts have package X, at which versions", previously installed).
- [x] Overview page: hosts (stale), open findings by severity, KEV,
      reboot pending, fix available / Pro-only / no fix, top 5 vulns.
- [x] shadcn components: `select`, `pagination` (host tabs are link tabs,
      so `tabs` wasn't needed).
- [ ] Fleet vulnerability list aggregates all of a user's findings
      (open + resolved) per request (per host via
      `findings_host_status_idx`, ~8 ms for 450 rows). If resolved history
      grows large, split the open and resolved paths or keep a per-user
      summary.
- [ ] Index `host_software (software_id) WHERE removed_at IS NOT NULL`
      for "previously installed/affected" fleet queries.
- [ ] 24 pre-existing files fail `oxfmt --check` (ui/*, nav-*, providers).

### Phase 1 remainder — alerting
Port exposure moved to host-side analysis in Phase 1.6 below; the
external scanner is deferred to Phase 2+ (DECISIONS.md "Port exposure").
- [x] Alert rule evaluation worker + dispatch (migration 0009,
      `internal/alerting`, `jobs/alerting.go`): rules on finding opened /
      reopened / resolved (min severity, KEV-only, host scope) and agent
      stale / recovered (`agent_health`, the dashboard's stale rule);
      dedup per (rule, event type, subject) within a window; digest mode;
      delivery with River retries/backoff and a per-attempt log.
- [x] Generalized notifier (`internal/notify`: `Notifier` interface,
      declared field schema, registry) with the **webhook** type:
      HMAC-SHA256-signed JSON POST ([WEBHOOKS.md](WEBHOOKS.md)), SSRF guard
      `internal/netguard` (https, ports 443/8443, public IPs checked at dial
      time, same-origin redirects; dev escape hatch
      `SW_NOTIFY_ALLOW_PRIVATE_NETWORKS`; a separate SMTP policy for the
      email channel, see below).
- [x] Dashboard: rules and delivery log with attempts under
      `/dashboard/alerts`; channels (form rendered from the type's schema,
      secret shown once + rotate, "Send test") under
      `/dashboard/settings/notifications`; all on `DataTable`, server
      actions scoped by `user_id`.
- [x] **ntfy** notifier (`internal/notify/ntfy`): JSON publish to ntfy.sh
      or a self-hosted server (topic validated against ntfy's charset,
      optional Bearer access token, automatic or fixed priority);
      human-readable title/body, priority from severity/KEV (KEV or
      critical → urgent, resolved/recovered → low, digests capped at high),
      emoji tags, `click` to the dashboard link. Through `netguard`, so a
      self-hosted server must be public https on 443/8443
      ([ARCHITECTURE.md § ntfy channel](ARCHITECTURE.md#ntfy-channel)).
- [x] **Email (SMTP)** notifier (`internal/notify/email`): plain-text mail
      through the user's own SMTP server. **SMTP settings are per channel**
      (host, port, security, username/password, from, to), entered in the
      channel form like webhook and ntfy; there is no platform-wide SMTP
      config (DECISIONS.md). Security STARTTLS (default, required when
      chosen), implicit TLS or none; certificates always verified.
      **"Allow insecure authentication"** (default off): credentials are
      never sent over a connection without TLS unless it is on. Subjects
      and bodies share ntfy's rendering (`internal/notify/render`); headers
      are CR/LF-safe, subjects RFC 2047 encoded. 4xx/connection errors are
      retried, 5xx/auth/TLS failures fail at once. `netguard` gained an
      **SMTP policy** (ports 25, 465, 587, 2525; same public-address
      checks at dial time and dev escape hatch; the https rules are
      unchanged)
      ([ARCHITECTURE.md § Email (SMTP) channel](ARCHITECTURE.md#email-smtp-channel)).
- MVP notification channels are **webhook + ntfy + email (SMTP)**;
  Discord and Slack are deferred to Phase 2+ (a webhook can already feed
  most chat tools).
- [ ] Encrypt channel secrets at rest (`notification_channels.secrets` is
      plaintext today; the worker needs the webhook secret to sign, so it
      would need a key shared by web + worker, e.g. `SW_SECRETS_KEY`).
- [x] Archived hosts don't alert: no finding events for them, and they're
      left out of agent events' `host_ids` / payload (`store/alerting.go`).
- [ ] Alerting: per-user rate limit / circuit breaker for a channel that
      keeps failing (today each delivery retries independently for ~11 h).
- [ ] Exposure events: see Phase 1.6 (a new event type + `Event` object,
      no dispatch changes).

### Phase 1.5 — agent/host split + Linux collector breadth
Design: [DOMAIN_MODEL.md §4](DOMAIN_MODEL.md#4-domain-model-agents-hosts-os-families).
Today agent == host: enrollment creates a `hosts` row and the returned
`agent_id` *is* `hosts.id`. Independent of P1a–c (new tables key on
`host_id`, which survives the split).
- [x] Migration `0008_agent_host_split`: `agents`, re-key
      `agent_credentials` to `agent_id`, `agent_hosts` (mode
      `local`/`ssh`/`winrm`, one local per agent), `host_identities`,
      `hosts.os_family` + current OS summary columns + `duplicate_of`,
      `snapshots.agent_id`/`facts`/`uptime_seconds` (`collector_status`
      already landed in P1a), `enrollment_tokens.agent_name`.
      Backfill with `agents.id = hosts.id` so deployed agents'
      `credentials.json` keeps working unchanged.
- [x] Enrollment creates an agent, not a host; host upserted on first push
      by identity (`/etc/machine-id`), so an agent reinstall reattaches to
      the existing host instead of duplicating it. Duplicate-identity
      flagging: Q12 resolved by recommendation (`hosts.duplicate_of`,
      never auto-merged). Rules and "active" in PROTOCOL.md "Host
      resolution".
- [x] Payload `agent` + `host` blocks (ref, identity, hostname refreshed
      every push, `os_family`) and per-collector status; payloads without
      a host block keep mapping to the agent's local host. Shipped within
      `schema_version: 1` (additive), so no v2 was needed. Ingest keeps
      `hosts.hostname` and the OS summary current from the newest
      snapshot.
- [x] Dashboard host management for the split (migration 0011, `mgmt_*`
      SQL functions + server actions): merge a flagged duplicate into its
      original / "not a duplicate", revoke an agent, request a credential
      rotation, rename / archive / delete a host, detach a host from an
      inactive agent. Rules in DOMAIN_MODEL §4.3 "Management".
- [ ] Agent/host reporting gaps: ~~`hosts.arch`~~ (done: agent `arch`
      collector → `os.arch`, `snapshots.arch`, `hosts.arch`);
      `hosts.os_build` is never written (only meaningful for the
      Windows/macOS agents); the production image build needs
      `--build-arg VERSION=...` so `agent.version` isn't `dev`.
- [x] Dashboard **Agents** page lists collectors (name, status online /
      stale / revoked / never connected, version, platform, host count,
      vuln pills, last seen) with their hosts as expandable sub-rows (OS,
      mode, last collected, findings, "Possible duplicate"), on the new
      shared `DataTable` (Q11). Optional agent name in the Register dialog.
- [x] Standalone **Hosts** list (`/dashboard/hosts`, DataTable: host /
      label, OS, collecting agents, open findings + severity/KEV, last
      seen, duplicate / archived / merged badges, State facet). Sidebar
      has Hosts and Agents; "Add host" and "Register agent" share one
      dialog (Q15).
- [x] Linux collectors (file/procfs reads only, per-collector status,
      capped with a `truncated` flag): uptime, arch, UDP listeners,
      systemd services (unit files + `*.wants` + `/proc/*/cgroup`, no
      D-Bus), local users (`/etc/passwd`/`/etc/group`), processes on
      deleted libraries (`/proc/*/maps`), unattended-upgrades config +
      last apt update (hostname + machine-id landed with the split,
      running kernel in P1b). PROTOCOL.md "Linux breadth sections".
- [x] Migration `0010_host_facts`: `host_services` / `host_listeners`
      (TCP+UDP) / `host_users` on the validity-range pattern, per-(host,
      kind) set hashes in `host_fact_state`, never closed when the
      collector isn't ok (truncated = additive only);
      `snapshots.uptime_seconds` / `arch` / `facts` (validated
      `hostfacts.LinuxFacts`), `hosts.arch`. Host tabs Services /
      Listeners / Users (DataTable), overview System + Needs restart,
      header arch/uptime/needs-restart badges.
- [ ] Follow-ups to the Linux collectors: services `failed` state (needs
      D-Bus or journal parsing); `needs_restart` misses other users'
      processes without `CAP_SYS_PTRACE` (counted as unreadable); service
      / listener / user changes on the History tab; fleet "which hosts
      listen on port N" page (`host_listeners_port_open_idx` is ready);
      retire `listening_sockets` (and its unused `is_public`) once
      exposure (Phase 1.6) reads `host_listeners` instead.
- [x] Remote collection over SSH for Linux (Q3–Q5 decided 2026-09-27;
      migration 0012, PROTOCOL.md §4): "Add host" → "Reach it from an
      existing agent", `GET /v1/agent/config` + `POST /v1/agent/status`,
      read-only SFTP collection with an agent-held key, user-confirmed
      host key pinning. Verified end to end against an OpenSSH container.
- [ ] Remote follow-ups: a "Replace agent" option at enrollment (new
      agent takes over the old one's remote hosts, dashboard lists hosts
      still needing its new public key); editing a remote host's address /
      port / user (today: delete and re-add); per-host status on the
      host's own pages (today: Hosts list badge + dialog); listeners and
      deleted-library facts for remote hosts (need walking remote /proc,
      slow over SFTP); collecting several targets in parallel; WinRM.
- [ ] Faster setup feedback for remote hosts (post-MVP): agent polls
      config every ~10s while any target is unconfirmed or failing (60s
      otherwise); a "Try again" button that clears a target's backoff;
      surface failed collectors (e.g. unreadable dpkg status) in the
      setup dialog instead of showing "Connected".

### Phase 1.6 — Docker inventory + host-side port exposure
Decided 2026-09-27 (DECISIONS.md "Port exposure" and "Docker
collection"). Generic Docker Engine support, including Swarm (managers
and workers), rootless Docker and Podman's Docker-compatible API; no
per-platform special-casing (Dokploy, Coolify…). Planned wire shape:
PROTOCOL.md "Docker sections". Order: the collector, then
storage/UI, then firewall + exposure on top.
- [x] Agent: Docker Engine API access through Docker's official Go client
      (`github.com/moby/moby/client`; decided 2026-09-28,
      DECISIONS.md "Docker collection") over the socket mounted into the
      agent container (`SW_DOCKER_SOCKET`, default
      `/var/run/docker.sock`), with API version negotiation and a pinned
      minimum. Collectors use it only through a small internal interface
      holding the reads they need: ping, version, info, container
      list/inspect, image list/inspect, network list, and on managers
      service/task/node list. Never logs, archive/export, image save,
      attach/exec, secrets or configs.
- [x] Agent: Docker collectors via that interface (`skipped` with a reason
      when the socket isn't mounted, so "no Docker" and "Docker not
      enabled" are normal states, distinct from `error`; `skipped` with
      a distinct reason on remote (SSH) targets, see below):
      `docker_engine` (version, API version, storage driver / image
      store, rootless, Swarm node id / cluster id / role),
      `docker_containers`, `docker_images`, `docker_networks`, and
      `swarm_services` (managers only; `skipped` on workers). The agent's
      wire types are the allowlist: only declared fields are sent (never
      `Env`, command lines, Swarm secret/config references), and labels
      only by exact key for Compose / stack / Swarm plus the
      `org.opencontainers.image.*` prefix (PROTOCOL.md "Never sent"),
      because labels routinely carry secrets (e.g. reverse-proxy
      basic-auth hashes). Mount sources only for bind mounts. SDK structs are
      mapped onto these wire types, never sent as-is. Caps + `truncated`
      like the other collectors.
- [x] Docker is collected **only on hosts with their own agent**
      (DECISIONS.md "Docker collection"): remote (SSH) targets report the
      Docker collectors `skipped` with reason "remote host" (their key is
      read-only SFTP, which can't reach the socket). The dashboard must
      make this obvious rather than showing an empty list, with three
      distinct states on the Containers / Images tabs and anywhere else
      Docker data appears (fleet images page, exposure):
      - **Remote host**: "Docker data needs an agent on this host. This
        host is collected over SSH by <agent>, which can only read
        files." Link to installing the agent on it.
      - **Local agent, socket not mounted**: "Docker collection isn't
        enabled on this agent", with the socket mount line and what it
        grants.
      - **Enabled, nothing running**: a normal empty state.
      Also: the "Reach it from an existing agent" option in the Add host
      dialog lists what remote collection doesn't cover (Docker,
      listeners, port exposure), so it's clear before the choice; and the
      host header shows a "Remote (SSH)" badge next to the collecting
      agent. (Done: the Add host list, the header's "Collected by" line
      with the badge, and the tabs' shared `docker-collection-state.tsx`,
      which also covers engine unreachable, collector error and an older
      agent build that reports no Docker status.)
- [x] Compose example + dashboard `docker run` line: Docker collection
      is **opt-in**, one socket mount with a comment saying plainly what
      it grants (full Docker API access, i.e. root-equivalent; the agent
      only makes the reads listed above). Docs for rootless Docker
      (`$XDG_RUNTIME_DIR/docker.sock`) and Podman (`podman.socket`).
      Register agent dialog: "Collect Docker containers and images"
      checkbox (default off); README "Docker collection (optional)".
      With `cap_drop: ALL` the agent (uid 0) connects only to sockets
      root owns; others need `group_add` with the socket's gid.
- [ ] Running the agent itself under rootless Docker / rootless Podman
      (as opposed to mounting a rootless engine's socket into a rootful
      agent, which is documented): `network_mode: host` is rootlesskit's
      network namespace there, not the host's, and `pid: host` / the
      `/:/host` mount behave differently, so listeners (and likely
      deleted-libs) would describe the wrong namespace. Verify on a real
      host; either document it as unsupported or detect and report the
      affected collectors `skipped`.
- [ ] Make opting out real: `/:/host:ro` is a recursive bind, so the
      host's `/run/docker.sock` is already reachable at
      `/host/run/docker.sock` whether or not the socket is mounted (`:ro`
      doesn't stop `connect()` on a socket). Reproduced 2026-09-27
      (Docker Desktop, Engine 29.8.0) with the agent's exact hardening
      (`cap_drop: ALL`, `no-new-privileges`, `read_only`, uid 0): `GET
      /version` and `POST /containers/create` both succeeded. The agent
      code never touches it. A non-recursive bind
      (`bind-recursive=disabled`, Docker 25+) hides the socket but also
      every nested mount: `/run` (the `reboot_required` collector reads
      `/host/run/reboot-required{,.pkgs}`) and any separately mounted
      `/var`, `/boot` or `/usr`. Options: non-recursive `/` plus explicit
      read-only binds for what the collectors read (not `/run` itself,
      it holds the socket); or masking known sockets (`docker.sock`,
      `containerd/*.sock`, `podman/*.sock`, `/run/user/*/docker.sock`),
      a fragile denylist. Verify on a real Ubuntu host.
- [x] Migration + ingest on the validity-range pattern (like
      `host_services`; done 2026-09-28, migration 0013, DOMAIN_MODEL.md
      §4.5 "Docker"): `container_images` interned fleet-wide by image
      ID (content-addressed: OS/arch, created, layer diff IDs, OCI
      labels); `host_images` (image present on a host, with that host's
      repo tags + repo digests); `host_containers` (keyed by container
      ID: name, image ref as configured + image ID actually run, state,
      started at, compose project/service, Swarm service/task/stack,
      published ports, networks, network mode, privileged, restart
      policy, mount types/paths); `swarm_services` per Swarm cluster
      (from any manager's push: name, image, mode/replicas, published
      ports with ingress/host mode). Per-kind set hashes in
      `host_fact_state`, never closed when the collector isn't `ok`.
- [x] Dashboard: host **Containers** tab (grouped by compose project or
      Swarm stack, published ports, image, state) and **Images** tab;
      containers/images changes on the History tab; fleet
      `/dashboard/images` ("which hosts run image X / digest Y") and a
      Swarm cluster view (services → nodes/tasks).
- [ ] Agent: `firewall` collector, file reads only (live netfilter state
      needs `CAP_NET_ADMIN`, which the agent won't get): ufw enabled
      (`/etc/ufw/ufw.conf`), default policies (`/etc/default/ufw`),
      rules (`/etc/ufw/user.rules`, `user6.rules`); Docker's
      `/etc/docker/daemon.json` (`iptables`, `ip`, `userland-proxy`,
      `data-root`). nftables / firewalld / raw iptables → reported as
      "other firewall" (unknown), not guessed.
- [ ] Server: exposure classification per open listener, from
      `host_listeners` + Docker published ports + Swarm published ports +
      firewall facts: local-only; **published by Docker (host firewall
      doesn't apply: Docker's rules are evaluated before ufw's)**; no
      host firewall; allowed by ufw; blocked by ufw; unknown (other
      firewall, Docker with `userland-proxy: false` and no Docker data).
      A listener owned by `docker-proxy` or `dockerd` on a wildcard
      address counts as Docker-published even without the Docker
      collector. Wording is "not protected by the host firewall", never
      "public": provider firewalls (e.g. Hetzner Cloud) are invisible to
      the agent. Remediation text differs per class (bind to
      `127.0.0.1:` / `DOCKER-USER` rules for Docker; a ufw rule
      otherwise).
- [ ] Exposure events (`exposure.port_exposed` / `exposure.port_closed`)
      on class transitions, through the existing alerting pipeline (a
      new event type + `Event` object, no dispatch changes); ignore
      expected ports per rule (e.g. 80/443 on a reverse proxy). Replace
      `TODO(phase 1, exposure)` in `ingest/handler.go`.

### Phase 2a — container image packages + vulnerabilities
Decided 2026-09-28 (DECISIONS.md "Container image vulnerabilities").
Scout-like, on our own pipeline: **inventory first, then matching**, as
for hosts. Every image shows all its packages (OS and language), and
vulnerabilities are a join on top. Package lists come from the server
where it can reach the image (registry SBOM, else pull + Syft) and from
the agent only where it can't; matching and scoring are always
server-side. No external API keys. Order: server-side public images
first (no agent upgrade needed), then more ecosystems, then the agent.
- [ ] Migration: `image_software` (image key as `container_images`:
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
- [ ] Worker: `image_sbom` River job, one per image key, enqueued when
      an image key is first seen with a repo digest. Fetch the registry's
      SBOM attestation for the digest (OCI referrers / Docker's
      `attestation-manifest` entries; SPDX and CycloneDX), anonymous
      registry auth, optional platform-wide Docker Hub token for the
      rate limit. Cache per image key fleet-wide; never refetch an `ok`
      one. Timeouts, size caps and `netguard` for outbound fetches.
- [ ] Matching: intern image packages into `software_versions` so the
      existing matcher, `software_vulnerabilities` and re-match
      triggers cover them; findings per host for images it runs
      (kind `vulnerable_image`, dedup key
      `img:<image_id>:<source>:<vuln_key>`), reconciled when an image is
      matched and when a host's image/container set changes. Ranking and
      KEV/EPSS/CVSS unchanged. Decide whether an image present but not
      used by any container gets findings or only a score.
- [ ] Dashboard: image detail page with **Packages** (all of them,
      vulnerable or not, filter by ecosystem, TanStack server-driven
      table) and **Vulnerabilities** tabs; score column on the fleet
      Images page and the host Images / Containers tabs (worst severity
      bucket + counts, max CVSS, KEV flag); explicit states for "no
      package list yet", "private/local image, needs the agent", and
      "ecosystem not assessed".
- [ ] Server-side Syft for public images without an SBOM attestation:
      pull by digest (the image's platform only) and run Syft as a Go
      library. Bound CPU, memory, disk and concurrency in the worker;
      delete pulled layers after cataloguing.
- [ ] Alpine: OSV `Alpine` ecosystem in `feeds.OSVEcosystems`, apk
      version comparator, `distro_releases` rows. Many official images
      ship `-alpine` variants, so this comes before language packages.
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
      whose metadata DB is locked, see DECISIONS.md "Docker
      collection" — verify how Syft or we resolve layers there) and
      sends only package URLs + paths, once per image. New wire section
      in PROTOCOL.md; adding it is a privacy decision (the list names
      the software in private images). Weigh the agent binary size cost.
      Keep `/var/lib/docker` / `/var/lib/containerd` readable when the
      `/:/host:ro` mount is narrowed (Phase 1.6), only with Docker on.
- [ ] Verification: compare our results with `docker scout cves` /
      Trivy / Grype on a fixed set of images (`postgres:17`,
      `nginx:1.27`, an Alpine variant, an EOL `debian:buster` image)
      and explain every difference.

### Cross-cutting gaps worth closing before real users
- [ ] Tests: dpkg status parsing, OS detection and the inventory range
      diff / set hash / old-agent rules now have tests (server store tests
      need `SW_TEST_DATABASE_URL`, otherwise skipped). Still missing: dpkg
      version comparison (once written), `/proc/net/tcp` parsing, and the
      ingest handler's auth path.
- [ ] No CI pipeline (build/test/lint on push) configured.
- [x] Agent credential rotation: `POST /v1/agent/rotate`, agent-initiated
      on a push-response signal (dashboard request, 90-day age, or use of
      the pre-rotation secret), 1h grace for the old secret, atomic
      `credentials.json` (PROTOCOL.md §3).
- [x] Host management UI: rename / archive / merge / delete on Hosts,
      revoke / rotate on Agents.
- [ ] `agent/docker-compose.example.yml` references
      `ghcr.io/icondesk/upkeep-agent:latest` (so does the dashboard's
      `docker run` line), which doesn't
      exist yet — needs a build/publish pipeline before that snippet is
      actually usable end-to-end.
- [ ] Release supply chain (the realistic way the agent gets
      compromised, and with the Docker socket mounted a bad release is
      root on every opted-in host): sign agent images (cosign) with SBOM
      + build provenance; release only from tagged commits in CI;
      versioned tags (not `:latest`) in the compose example and the
      dashboard snippet so a bad release doesn't auto-propagate; 2FA and
      branch protection on the publishing account, narrowly scoped
      publish tokens.
- [x] Expired-enrollment-token cleanup: hourly River `credential_cleanup`
      job in the worker (also clears expired post-rotation secrets).
- [ ] `server/Dockerfile` runtime base (`alpine:3.20`) wasn't covered by
      the last version audit — check it.

### Phase 2+ (explicitly deferred, don't start early)
- [ ] External port-exposure scanner (deferred 2026-09-27, DECISIONS.md
      "Port exposure"): probe only an enrolled agent's own
      `snapshots.source_ip`, rate-limited, never an arbitrary target;
      skip private / CGNAT / loopback source IPs ("can't verify"); remote
      (SSH) hosts ineligible (Q5). Its vantage point is the platform
      box, not the internet, which self-hosters' private networks and
      allowlists make misleading.
- [ ] RHEL/Alpine package collectors (agent currently Debian/Ubuntu-only
      by design).
- [ ] SMS notifications.
- [ ] Discord notifier (webhook URL as a secret field, embed formatting).
- [ ] Slack notifier (incoming-webhook URL; Block Kit formatting).
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
> [DOMAIN_MODEL.md](DOMAIN_MODEL.md) (open questions Q1, Q3). Q3 is
> decided (2026-09-27): agent-initiated remote collection over SSH is in
> scope (Linux, read-only SFTP). Until Q1 is decided, the rest stands. "Remote command execution" here means
> the *server* causing execution on a host, and stays excluded either
> way.
