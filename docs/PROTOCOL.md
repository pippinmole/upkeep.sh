# Agent ↔ Server Protocol

The agent is outbound-only: it never opens a listening port, and the
server never connects to it. Everything below is initiated by the agent.

## 1. Enrollment

One-time, per **agent**. The dashboard generates a token
(`enrollment_tokens` table, 1-hour expiry, optional `agent_name`) via the
"Register agent" / "Add host" button (`web/src/app/dashboard/actions.ts`).

```
POST /v1/enroll
Content-Type: application/json

{ "enrollment_token": "<token>", "hostname": "my-vps",
  "version": "0.3.0", "platform": "linux/amd64" }
```

`version` and `platform` (the agent build, `GOOS/GOARCH`) are optional;
agents that predate them omit them and report them in each push's `agent`
block instead.

→ `200 OK`

```
{ "agent_id": "<uuid>", "agent_secret": "<random>" }
```

Enrollment creates an `agents` row (named after the token's
`agent_name`, else `hostname`) and its `agent_credentials` row, in one
transaction that also deletes the token (`EnrollAgent` in
`server/internal/store/agents.go`), so the token can't be replayed even if
leaked after use. **No host is created**: the host is created, or
re-attached by identity, on the agent's first push (see `host` below).
Before migration 0008 enrollment created a host and `agent_id` was its
`hosts.id`; the migration gave every such host an agent with the same
id, so existing `credentials.json` files keep working unchanged. `agent_secret` is generated with 32 bytes of `crypto/rand`
(`server/internal/authn/secret.go`); only its SHA-256 hash is ever stored
server-side. The agent persists both values to
`SW_DATA_DIR/credentials.json` (mode `0600`) and re-enrolls only if that
file is missing (`agent/cmd/agent/enroll.go`).

## 2. Snapshot push

Repeats on `SW_INTERVAL` (default 15m).

```
POST /v1/snapshots
X-Agent-ID: <agent_id>
Authorization: Bearer <agent_secret>
Content-Type: application/json

{
  "schema_version": 1,
  "collected_at": "2026-09-26T12:00:00Z",
  "agent": { "version": "0.3.0", "platform": "linux/amd64", "interval_seconds": 900 },
  "host": {
    "ref": "local",
    "os_family": "linux",
    "hostname": "web-1",
    "identity": { "machine_id": "0123456789abcdef0123456789abcdef" }
  },
  "os": { "id": "ubuntu", "version_id": "22.04", "codename": "jammy",
          "kernel": "6.8.0-45-generic" },
  "collectors": {
    "os":              { "status": "ok" },
    "kernel":          { "status": "ok" },
    "host_identity":   { "status": "ok" },
    "deb_packages":    { "status": "ok" },
    "tcp_listeners":   { "status": "ok" },
    "udp_listeners":   { "status": "ok" },
    "reboot_required": { "status": "ok" },
    "public_ip":       { "status": "ok" },
    "uptime":          { "status": "ok" },
    "arch":            { "status": "ok" },
    "systemd_services": { "status": "ok" },
    "local_users":     { "status": "ok" },
    "deleted_libs":    { "status": "ok" },
    "unattended_upgrades": { "status": "ok" }
  },
  "packages": [
    { "name": "libssl3", "version": "3.0.2-0ubuntu1.15", "arch": "amd64",
      "source": "openssl", "source_version": "3.0.2-0ubuntu1.15",
      "ecosystem": "deb" }
  ],
  "listening_sockets": [
    { "proto": "tcp", "local_addr": "0.0.0.0", "port": 5432,
      "pid": 1234, "process_name": "postgres" }
  ],
  "reboot_required": false,
  "reboot_required_packages": [],
  "public_ipv4": "203.0.113.7",
  "public_ipv6": "2001:db8::1"
}
```

### `agent`

The agent build that collected the snapshot (not the host): `version`
(`-X main.version` at build time, `dev` otherwise), `platform`
(`GOOS/GOARCH` of the agent binary) and `interval_seconds` (its
`SW_INTERVAL`). Stored on the `agents` row every push; empty fields leave
the stored value alone. The interval decides when the agent stops counting
as **active** (see "Host resolution"). Omitted by older agents.

### `host`

Which host the snapshot describes, and what it is. The agent works this
out itself by reading the host's filesystem (`agent/internal/detect`);
it is never told.

- `ref`: the target within this agent. Always `"local"` today (the machine
  the agent runs on). Reserved for remote target names later
  (DOMAIN_MODEL.md §4.2), which are not implemented.
- `os_family`: `"linux"`, `"windows"`, `"macos"`, or `""` if detection
  failed (see `collectors.os`). Linux is detected from
  `/etc/os-release` (falling back to `/usr/lib/os-release`); Windows and
  macOS from marker files, family only.
- `hostname`: from the host's `/etc/hostname`, refreshed every push
  (enrollment's `hostname` is only the initial value). Omitted if the file
  is missing.
- `identity.machine_id`: the host's `/etc/machine-id`. This is the key the
  server upserts hosts on (`host_identities`, kind `machine_id`,
  lowercased), so a reinstalled agent re-attaches to its host. Omitted when unreadable, empty or
  `uninitialized`; `collectors.host_identity` is then `error`.

Snapshots from agents that predate the host block omit it entirely. They
are the authenticating agent's local host, with no identity; their
`os_family` is taken to be `linux` (the only agent that existed).

#### Host resolution (server)

`store.resolveHost`, inside the snapshot transaction, after the agent is
authenticated:

- `ref` other than `"local"` must match an existing `agent_hosts`
  assignment (`target_ref`), else `422`. None exist yet: remote targets
  will be created in the dashboard, never by a push.
- `ref: "local"`, the agent already has a local host: the push goes to
  it (assignments are sticky). An unclaimed `machine_id` is recorded for
  it; a `machine_id` already owned by another host flags this one
  `hosts.duplicate_of` that host.
- First push of an agent, `machine_id` unknown (missing, empty,
  `uninitialized`, or `collectors.host_identity` not `ok`): a new host is
  created for the agent. Later pushes reuse it through the assignment, so
  a host is never duplicated per push.
- First push, `machine_id` unclaimed within the agent's user: a new host,
  with that identity.
- First push, `machine_id` owned by host H: if no **other active** agent
  has H as its local host, the agent re-attaches to H and its history
  (reinstall). Otherwise a new host is created with
  `duplicate_of = H` (cloned VM or a second agent on one machine;
  DOMAIN_MODEL.md Q12). Hosts are never merged automatically.

An agent is **active** when `agents.revoked_at` is NULL and it pushed
within `max(3 × interval, 2 minutes)`, where the interval is its reported
`interval_seconds`, else 15 minutes.

Every push then sets `agents.last_seen_at` (and version/platform/interval),
`agent_hosts.last_collected_at`, `hosts.last_seen_at`, and, when the
snapshot is the host's newest by `collected_at`: `hosts.hostname` (when
sent), `hosts.os_family`, `os_id`, `os_version`, `os_codename` (when
`collectors.os` is `ok`) and `hosts.kernel` (the trusted `os.kernel`, NULL
when unknown). `snapshots.agent_id` records the agent.

### `collectors`

One entry per collector the agent build knows, every push:

| `status` | Meaning | Section |
|---|---|---|
| `ok` | Collected. | Authoritative, even if empty. |
| `error` | Applicable to this host, but failed. `error` holds the message. | **Unknown.** Must not be treated as empty. |
| `skipped` | Not applicable to this host (OS family/distro), or the target can't provide it. `reason` says why. | Absent / meaningless. |

Collector names and the sections they own:

| Collector | Owns | Applies to |
|---|---|---|
| `os` | `os` (except `os.kernel`), `host.os_family` | always |
| `kernel` | `os.kernel` | Linux with live procfs (local target) |
| `host_identity` | `host.hostname`, `host.identity` | Linux |
| `deb_packages` | `packages` entries with `ecosystem: "deb"` | Debian-like Linux (`ID` or `ID_LIKE` contains `debian`/`ubuntu`) |
| `tcp_listeners` | `listening_sockets` entries with `proto` `tcp`/`tcp6` | Linux with live procfs (local target) |
| `udp_listeners` | `listening_sockets` entries with `proto` `udp`/`udp6` | Linux with live procfs (local target) |
| `reboot_required` | `reboot_required`, `reboot_required_packages` | Debian-like Linux |
| `public_ip` | `public_ipv4`, `public_ipv6` | local target (best-effort: `ok` with no IPs is normal) |
| `uptime` | `uptime_seconds` | Linux with live procfs |
| `arch` | `os.arch` | Linux |
| `systemd_services` | `services` (`manager: "systemd"`) | Linux with systemd unit directories (else `skipped`) |
| `local_users` | `users` | Linux |
| `deleted_libs` | `facts.needs_restart` | Linux with live procfs |
| `unattended_upgrades` | `facts.unattended_upgrades` | Debian-like Linux |

A collector whose list hit the agent's size cap reports
`{"status": "ok", "truncated": true}` and sends a deterministic prefix
(sorted by key). The server treats a truncated section as **additive
only**: it opens and replaces rows, never closes one it doesn't list.
Caps: 1000 listeners per transport, 2000 services, 2000 users, 200
processes × 20 libraries for `needs_restart`.

Future package sources (rpm, apk, Windows programs, Homebrew…) each add
their own `<ecosystem>_packages`-style collector and their own
`ecosystem` value. A host may have several; each succeeds or fails on its
own.

**Rule for the server: a failed collector is never a removal.** Package
inventory is diffed **per ecosystem**, and only for ecosystems whose
collector is `ok`. When `deb_packages` is `error`, the host's open
`deb` ranges stay exactly as they are. `packages` is `null` when no
package collector succeeded, and `[]` only when one succeeded and found
nothing. Payloads without `collectors` come from older agents, which
never pushed on a collector failure, so their sections are all
authoritative.

How the server applies this (`planInventory` in
`server/internal/ingest/inventory.go`):

- `packages` null or absent: no ecosystem is diffed.
- With `collectors`: ecosystem `E` is diffed iff `E_packages` is `ok`,
  even when no `E` packages are listed (then all its ranges close).
  Packages of any other ecosystem are ignored for inventory.
- Without `collectors` (older agents): a non-empty `packages` is an ok
  `deb` source. An empty `packages` is **not** treated as authoritative,
  since zero installed packages on a Debian-like host is implausible and
  closing every range is the expensive mistake.
- `deb` also needs a known OS (`os.id` set, and `collectors.os` ok when
  present), because interned versions are scoped by distro and release.
- A push not newer than the last applied inventory for that ecosystem
  (by `collected_at`, clamped to server time) is stored but not diffed.

A collector failure no longer aborts the push. Before the collectors
block existed, a dpkg error meant no snapshot at all.

### `os.kernel`

The running kernel release, exactly what `uname -r` prints
(`"6.8.0-45-generic"`, `"6.1.0-18-amd64"`), read from
`/proc/sys/kernel/osrelease` of the target's live procfs (a file read;
the agent never executes `uname`). The kernel release is global to the
kernel, not namespaced, so the agent container's own `/proc` gives the
host's value; `/host/proc` is not used. Omitted when the `kernel`
collector is not `ok`; added within `schema_version` 1, so older agents
omit it too.

The server stores it as `snapshots.kernel_release` and uses the newest
snapshot's value as the host's running kernel: kernel CVE findings are
raised only for installed kernel packages belonging to that release
(DOMAIN_MODEL.md Q7). It is trusted only when `collectors.kernel` is `ok`
(or, for payloads without `collectors`, when present at all). When it is
unknown, every installed kernel raises findings, flagged
`running_kernel_unknown`.

### `packages`

| Field | Meaning |
|---|---|
| `name`, `version`, `arch` | The binary package as installed. |
| `source`, `source_version` | The source package it was built from. Debian/Ubuntu advisories are keyed by source package and version (DOMAIN_MODEL.md §2.5). From dpkg's `Source:` field: absent means the same as the binary; `Source: foo` means source `foo` at the binary's version; `Source: foo (1.2-3)` gives an explicit source version (binNMUs). Always set by this agent; older agents omit both. |
| `ecosystem` | Which package source reported it: `"deb"` (dpkg). Keys `software_versions.ecosystem`. Older agents omit it; treat as `"deb"`. |

Only packages whose dpkg `Status:` state (third word) is `installed`,
`triggers-pending` or `triggers-awaited` are sent. The trigger states mean
the package's files are fully on disk and only a trigger is outstanding;
apt runs triggers in batches, so excluding them would make a push that
lands mid-upgrade record false remove/re-add history. `half-installed`,
`not-installed`, `config-files`, `unpacked` and `half-configured` are
excluded.

### Linux breadth sections (added within `schema_version` 1)

All are file / procfs reads; the agent never executes anything. Each is
**authoritative only when its collector is `ok`** (never inferred from
presence: `services` and `users` are omitted when empty). The server
folds `services`, `users` and the listeners into validity ranges
(`host_services`, `host_users`, `host_listeners`, migration 0010) per
kind (`services:systemd`, `users:local`, `listeners:tcp`,
`listeners:udp`), with a set hash per (host, kind) in `host_fact_state`
that skips unchanged pushes, and the same stale-push rule as packages. A
kind whose collector isn't `ok` keeps its open ranges untouched. Payloads
without `collectors` (older agents) are authoritative for TCP listeners
only.

```
"os": { ..., "arch": "amd64" },
"uptime_seconds": 350735,
"listening_sockets": [
  { "proto": "udp", "local_addr": "127.0.0.53", "port": 53, "pid": 610,
    "process_name": "systemd-resolve" }
],
"services": [
  { "manager": "systemd", "name": "ssh.service",
    "display_name": "OpenBSD Secure Shell server",
    "start_mode": "auto", "state": "running", "run_as": "root",
    "binary_path": "/usr/sbin/sshd",
    "attrs": { "unit_path": "/lib/systemd/system/ssh.service" } }
],
"users": [
  { "name": "ubuntu", "uid": 1000, "gid": 1000, "home": "/home/ubuntu",
    "shell": "/bin/bash", "groups": ["ubuntu", "adm", "sudo"],
    "login_shell": true, "admin": true }
],
"facts": {
  "needs_restart": {
    "processes": [ { "pid": 812, "name": "sshd", "unit": "ssh.service",
                     "libraries": ["/usr/lib/x86_64-linux-gnu/libssl.so.3"] } ],
    "unreadable_processes": 3
  },
  "unattended_upgrades": {
    "package_installed": true, "update_package_lists": "1",
    "unattended_upgrade": "1", "enabled": true,
    "last_apt_update": "2026-09-26T06:12:00Z",
    "last_apt_update_source": "update-success-stamp",
    "last_unattended_run": "2026-09-26T06:30:00Z"
  }
}
```

- `uptime_seconds`: whole seconds from `/proc/uptime` (not namespaced, so
  the container's `/proc` gives the host's). Stored in
  `snapshots.uptime_seconds`.
- `os.arch`: Debian architecture name. From the `Architecture` of the
  installed `dpkg` package (dpkg is Essential and built for the native
  arch, so this is `dpkg --print-architecture`, and it describes the
  userland that package matching is about, even with a 64-bit kernel on
  a 32-bit userland); else `/proc/sys/kernel/arch` (`uname -m`, Linux
  6.1+) mapped to Debian names (`x86_64` → `amd64`, `aarch64` → `arm64`,
  …). Stored in `snapshots.arch` and, from the newest snapshot, in
  `hosts.arch` (kept when a later push doesn't know it).
- UDP listeners: UDP has no listen state, so a socket counts when it is
  bound to a non-zero local port and **unconnected** (`/proc/net/udp{,6}`
  state `07` with an all-zero remote endpoint). A connected UDP socket
  (DNS client, state `01`) only accepts its peer's datagrams and is not
  a listener. The agent deduplicates all sockets on (proto, address,
  port), since `SO_REUSEPORT` lets several share one. Addresses are
  canonical (`::`, `::ffff:127.0.0.1`), no longer zero-padded.
- `services` (systemd, no D-Bus): unit files from `/etc/systemd/system`,
  `/run/systemd/system`, `/usr/local/lib/systemd/system`,
  `/lib/systemd/system`, `/usr/lib/systemd/system` (first wins, drop-ins
  applied). `start_mode`: `masked` (symlink to `/dev/null` or empty
  file), `auto` (linked from any `*.wants/`, `*.requires/`, `*.upholds/`,
  i.e. started at boot), `manual` (an enabled same-named `.socket`,
  `.timer` or `.path` starts it; `attrs.activated_by`), `static` (no
  `[Install]` section), else `disabled`. `state` is `running` when any
  process's `/proc/<pid>/cgroup` is `…/system.slice/…/<unit>` (works
  across the agent's cgroup namespace), else `stopped`; omitted without
  procfs, and there is no `failed`. `run_as` is `User=`, `root` when
  unset, empty with `attrs.dynamic_user` for `DynamicUser=yes`.
  Template instances are reported when wanted or running; transient
  units (no unit file) are not. Unit files or drop-ins the agent can't
  read (permission denied, e.g. netplan's root-only generator units)
  don't fail the collector: the service is still reported, their paths
  are listed in `attrs.unreadable`, and `start_mode`/`run_as` are left
  empty when they depend on the unread file. An unlistable unit
  directory marks the section `truncated`.
- `users`: `/etc/passwd` + `/etc/group` (never `/etc/shadow`). `groups`
  is the primary group then supplementary groups. `login_shell` is false
  for `nologin`/`false`/`true`/`sync`/`shutdown`/`halt`; `admin` is uid 0
  or membership of `sudo`, `wheel`, `adm` or `admin`.
- `facts` is stored per snapshot in `snapshots.facts` after validation
  against a Go struct (`hostfacts.LinuxFacts`): unknown members dropped,
  sizes clamped, members whose collector isn't `ok` removed; a malformed
  block is logged and stored as `{}` without failing the push.
  - `needs_restart`: processes whose `/proc/<pid>/maps` still maps a
    deleted shared object (`*.so*`, suffixed ` (deleted)`), with the
    systemd unit to restart. Reading another user's maps needs
    `CAP_SYS_PTRACE`, which the agent doesn't have: those are counted in
    `unreadable_processes`, so the list is complete only when that is 0.
  - `unattended_upgrades`: `APT::Periodic::Update-Package-Lists` /
    `::Unattended-Upgrade` from all of `/etc/apt/apt.conf.d` (lexical
    order, then `/etc/apt/apt.conf`, flat syntax only); `enabled` = a
    non-zero interval and the package not known to be missing; last apt
    update from the mtime of `/var/lib/apt/periodic/update-success-stamp`,
    else of `/var/lib/apt/lists`.

`listening_sockets` is still stored per snapshot (TCP and UDP rows, first
of each primary key) in addition to the `host_listeners` ranges: it keeps
the owning pid, which ranges deliberately don't (it would churn on every
restart), and `is_public` for the planned exposure scanner.

### Other fields

`reboot_required` / `reboot_required_packages` come from the host's
`/run/reboot-required{,.pkgs}`. The agent reads `/run` directly, not
`/var/run`: on modern hosts `/var/run` is an absolute symlink to `/run`,
which under the `/:/host` bind mount would resolve inside the agent's own
container.

`public_ipv4` / `public_ipv6` are the agent's own best-effort belief about
its public address(es) (looked up via an outbound-only call to ipify, the
agent's only third-party network call). Either or both may be omitted when
unavailable (no route for that family, DNS failure, lookup timeout) — this
is normal and never fails the push. This is **separate** from the
server-observed `source_ip` recorded from the push connection itself (see
`clientIP()` below): the agent's belief about its own address and what the
server actually saw connect can legitimately differ (extra NAT hops,
asymmetric routing), and the two serve different purposes.

→ `202 Accepted` on success.

Auth: `X-Agent-ID` is an `agents.id`. The bearer secret is verified in
constant time (`authn.VerifySecret`) against the hash stored for that
agent; a revoked agent (`agents.revoked_at` set) gets `401`. There is no
shared platform-wide credential — each agent has its own scoped secret.

The server keeps **every** historical snapshot (not an upsert) so drift
and findings history stay auditable — see `store.InsertSnapshot`. Package
inventory is additionally folded into validity ranges (`host_software`)
in the same transaction; `snapshots.schema_version` stores the payload's
value. Vulnerability matching never runs in the request: when the push
interned new package versions, changed the inventory, or changed the
running kernel, ingest enqueues `match_versions` / `reconcile_host` jobs
in the same transaction (River `InsertTx`), and the worker process runs
them (ARCHITECTURE.md "Vulnerability pipeline").

`clientIP()` in `server/internal/ingest/handler.go` prefers
`X-Forwarded-For` because production sits behind Dokploy/Coolify's
Traefik proxy. **The reverse proxy must set/overwrite this header
itself** — it is later used to verify that an external port scan only
ever targets an enrolled agent's own IP (not yet built), so trusting an
unproxied value here would let anyone spoof their source IP.

## Types

Canonical Go types live in `agent/internal/collector/types.go` (the
agent's view) and `server/internal/ingest/payload.go` (the server's
view). These are **independent types, not a shared module** — the JSON
wire format is the actual contract, which is what lets `schema_version`
decouple server and already-deployed-agent upgrades. Keep them in sync
manually; a mismatch should only ever be an additive field.

## Versioning

- `collector.SchemaVersion` (agent) / `ingest.CurrentSchemaVersion`
  (server) — bump for the payload shape the *current* agent build sends.
- `ingest.MinSupportedSchemaVersion` — the oldest payload shape the
  server still accepts. A push below this is rejected with `400`.
- Additive fields never require a bump. Only bump on a breaking shape
  change, and document the migration path for already-deployed agents
  before doing so (they can't be force-upgraded — it's push-only).
- `agent`, `host`, `collectors`, the package `source` / `source_version` /
  `ecosystem` fields, and the Linux breadth sections (`uptime_seconds`,
  `os.arch`, UDP entries in `listening_sockets`, `services`, `users`,
  `facts`, `collectors.*.truncated`) were added **within
  `schema_version: 1`**. A server that predates the breadth sections
  ignores them, and stores UDP entries in `listening_sockets` as it does
  TCP (the agent's dedupe keeps its primary key unique). The
  server's decoder ignores unknown fields, so servers that predate them
  keep accepting these pushes. A newer server detects them by presence:
  no `collectors` means a pre-collectors agent (all sections
  authoritative), no `host` means the agent's local host, no `source`
  means source = binary. DOMAIN_MODEL.md §4.4 sketched these under a v2;
  v2 remains reserved for a genuinely breaking change, such as one
  request carrying several hosts.

## Not yet implemented

- Beyond the inventory diff, snapshot processing is insert-only — see the
  `TODO(phase 1)` in `handler.go`. Vulnerability matching and port-exposure evaluation
  are meant to be enqueued per snapshot once those workers exist, not run
  inline in the request handler.
- No credential rotation endpoint yet (only initial enrollment).
  Revocation is `agents.revoked_at`; no dashboard action sets it yet.
- No agent self-update.
