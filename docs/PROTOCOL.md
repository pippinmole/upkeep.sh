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
`SW_DATA_DIR/credentials.json` (mode `0600`, written atomically: temp file,
fsync, rename) and re-enrolls only if that file is missing
(`agent/cmd/agent/enroll.go`, `credentials.go`). The secret can later be
replaced by rotation (section 3).

`SW_DATA_DIR` (default `/var/lib/upkeep`; an agent whose credentials are
still under the pre-rename `/var/lib/security-whatnot` keeps using that)
is a directory, not a file: it also holds the agent's SSH key for remote
targets (`ssh/id_ed25519`, section 4). It must be a persistent, writable
volume (`-v upkeep-agent-data:/var/lib/upkeep`). The agent checks it can
write there **before** spending the one-time token, so a read-only
container without the volume fails with a clear error and the token stays
usable.

## 2. Snapshot push

Authentication: `X-Agent-ID` + `Authorization: Bearer <agent_secret>`,
checked against the agent's current secret, or its previous one during a
post-rotation grace window (section 3). Unknown agent, wrong secret or a
revoked agent (`agents.revoked_at`, set by "Revoke" in the dashboard):
`401`.

A `202` may carry `X-Upkeep-Rotate-Credentials: 1`: the server asks the
agent to rotate its credential now (section 3). Agents that predate
rotation ignore the header.

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
    "unattended_upgrades": { "status": "ok" },
    "host_mount":      { "status": "ok" }
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
  "reboot_required_source": "kernel",
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
| `reboot_required` | `reboot_required`, `reboot_required_packages`, `reboot_required_source` | Debian-like Linux (`skipped` when neither signal can decide, see "Other fields") |
| `public_ip` | `public_ipv4`, `public_ipv6` | local target (best-effort: `ok` with no IPs is normal) |
| `uptime` | `uptime_seconds` | Linux with live procfs |
| `arch` | `os.arch` | Linux |
| `systemd_services` | `services` (`manager: "systemd"`) | Linux with systemd unit directories (else `skipped`) |
| `local_users` | `users` | Linux |
| `deleted_libs` | `facts.needs_restart` | Linux with live procfs |
| `unattended_upgrades` | `facts.unattended_upgrades` | Debian-like Linux |
| `host_mount` | nothing (a health check) | the agent in a container (`skipped` on bare metal and remote targets): `error` when any host unix socket is reachable under the host root, listing them and the fix |

A collector whose list hit the agent's size cap reports
`{"status": "ok", "truncated": true}` and sends a deterministic prefix
(sorted by key). The server treats a truncated section as **additive
only**: it opens and replaces rows, never closes one it doesn't list.
Caps: 1000 listeners per transport, 2000 services, 2000 users, 200
processes × 20 libraries for `needs_restart`.

In the container deployment the agent reads the host's files through
`/host` (the host's `/`, bound non-recursively) and `/host-extra`
(`var/lib/dpkg`, `var/lib/apt`, `run/systemd/system`; see
`agent/docker-compose.example.yml`). A file a collector needs that isn't
visible there is an `error` naming the path and the mount to check
(`deb_packages`, `local_users`, `unattended_upgrades`, and
`systemd_services` when PID 1 is systemd), never an empty `ok`.
`host_mount` owns no section and the server stores it like any other
status (`snapshots.collector_status`); an `error` means the agent can
connect to host control sockets (docker.sock, containerd, D-Bus,
systemd) whether or not Docker collection is on. The `host_mount`
collector and `reboot_required_source` are additive: older servers
ignore them, and older agents simply don't send them.

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
restart). Its `is_public` column is never set: the external scanner it
was meant for is deferred ([decisions/port-exposure.md](decisions/port-exposure.md)).

### Docker sections

[tasks/phase-1-6-docker-exposure.md](tasks/phase-1-6-docker-exposure.md); rationale in [decisions/docker-collection.md](decisions/docker-collection.md). The
agent sends these (agent/internal/collector/types_docker.go); the server
stores them per migration 0013 (see "Server storage" at the end of this
section). Additive within `schema_version: 1`, like the breadth sections.

The agent reads the Docker Engine API over the socket mounted into its
container (`SW_DOCKER_SOCKET`, default `/var/run/docker.sock`; opt-in),
through Docker's Go SDK, calling only a fixed list of read endpoints.
Local targets only: on remote (SSH) targets every Docker collector is
`skipped` with reason "remote host", which the dashboard shows as
"needs an agent on this host". New collectors, each with its own status:

| Collector | Owns | Applies to |
|---|---|---|
| `docker_engine` | `docker.engine`, `docker.swarm` | local target with the socket mounted (else `skipped`: "docker socket not mounted" / "remote host"; engine unreachable is `error`) |
| `docker_containers` | `docker.containers` | engine reachable |
| `docker_images` | `docker.images` | engine reachable |
| `docker_networks` | `docker.networks` | engine reachable |
| `swarm_services` | `docker.swarm_services` | Swarm manager (`skipped` on workers and outside Swarm) |

```
"docker": {
  "engine": { "version": "29.8.0", "api_version": "1.56",
              "storage_driver": "overlayfs", "image_store": "containerd",
              "rootless": false },
  "swarm": { "state": "active", "node_id": "…", "cluster_id": "…",
             "role": "manager" },
  "containers": [
    { "id": "8e89…", "name": "myapp-db-1", "image": "postgres:18",
      "image_id": "sha256:…", "state": "running",
      "started_at": "2026-09-27T10:00:00Z",
      "labels": { "com.docker.compose.project": "myapp",
                  "com.docker.compose.service": "db" },
      "ports": [ { "host_ip": "0.0.0.0", "host_port": 5432,
                   "container_port": 5432, "proto": "tcp" } ],
      "networks": ["myapp_default"], "network_mode": "bridge",
      "privileged": false, "restart_policy": "unless-stopped",
      "mounts": [ { "type": "volume", "destination": "/var/lib/postgresql",
                    "rw": true },
                  { "type": "bind", "source": "/srv/myapp/backups",
                    "destination": "/backups", "rw": true } ] }
  ],
  "images": [
    { "id": "sha256:…", "repo_tags": ["postgres:18"],
      "repo_digests": ["postgres@sha256:…"], "created": "…",
      "os": "linux", "arch": "arm", "variant": "v7",
      "layers": ["sha256:…"],
      "labels": { "org.opencontainers.image.version": "18.0" } }
  ],
  "networks": [ { "id": "…", "name": "myapp_default", "driver": "bridge",
                  "scope": "local", "internal": false,
                  "subnets": ["172.18.0.0/16"] } ],
  "swarm_services": [
    { "id": "…", "name": "web_api", "image": "ghcr.io/me/api:1@sha256:…",
      "mode": "replicated", "replicas": 2,
      "running_tasks": 2, "desired_tasks": 2,
      "labels": { "com.docker.stack.namespace": "web" },
      "ports": [ { "published": 443, "target": 8443, "proto": "tcp",
                   "publish_mode": "ingress" } ] }
  ]
}
```

- **Never sent**: environment variables, command lines, Swarm secrets or
  configs, volume names and driver options, mount sources other than a
  bind mount's host path, and labels outside the allowlist. Labels are
  matched by **exact key** for Compose / stack / Swarm (the keys those
  tools set themselves: project, service, container number, config hash,
  stack namespace, Swarm service/task/node ids…; anyone can put a secret
  under a Docker-owned prefix in their own compose file), and by prefix
  only for `org.opencontainers.image.*`. The Compose
  `project.config_files` / `project.working_dir` /
  `project.environment_file` labels are kept: host paths, never file
  contents. Enforced by the agent's wire types (only declared fields are
  serialized) and `FilterDockerLabels`.
- Status reasons are exact strings the dashboard keys on: `"remote host"`
  (all five, SSH targets; the socket is never touched), `"docker socket
  not mounted"` (all five; nothing at `SW_DOCKER_SOCKET`), and when
  something is there but unusable (refused, permission, API older than
  1.41) `docker_engine` is `error` and the other four are skipped `"docker
  engine unavailable"`. `swarm_services` is skipped `"not in a swarm"`,
  `"not a swarm manager"` or `"swarm locked"` (also when the node's role
  changes between `/info` and the service list). A Docker collector
  missing from `collectors` means that agent build doesn't have it: not
  authoritative.
- `engine.api_version` is the engine's highest supported API version
  (`/version`), not the one the agent negotiated. `swarm` is sent for
  active Swarm members (`state: "active"`, with `node_id` and `role`)
  and for locked (autolock) managers as `{"state": "locked"}`: while
  locked the engine reports no role or cluster and usually no node id.
  Pending / error nodes send no `swarm` block.
- `swarm_services[].running_tasks` / `desired_tasks` are current values
  from the service status (absent when the engine doesn't return it,
  e.g. older APIs / Podman), stored as current state, not history.
  `ports` are the allocator-assigned endpoint ports, falling back to the
  spec's before allocation; `published` is absent when none is assigned
  yet or for a host-mode port without a fixed one. `image` is empty for
  plugin services. **Gap:** job services (`replicated-job` /
  `global-job`) send no `replicas` and no target (completions /
  concurrency); revisit with the Swarm cluster view.
- Containers: `ports` is what is published now (the live port map):
  stopped containers have none, exposed-only ports have no `host_ip` /
  `host_port`, identical entries appear once (0.0.0.0 and :: stay
  separate). `image` is the configured reference (`Config.Image`).
  `started_at` / image `created` are RFC3339 UTC; the engine's zero time
  is omitted, 1970-01-01 is a real value.
- `inspect_error` (containers and images): the object was listed but
  inspecting it failed with something other than "not found". The entry
  is partial: a container carries only `id`, `name`, `image`,
  `image_id`, `state`, `labels`; an image only `id`, `repo_tags`,
  `repo_digests`, `created`, `labels`. Every other field is unknown, not
  false or empty (`privileged` is absent). The object still exists, so
  the server keeps its validity range open and the dashboard shows it
  with details unavailable. At most 256 bytes of error text. The
  collector stays `ok` (`truncated` still only means a cap was hit). An
  object removed between list and inspect (404) is simply absent. The
  collector is `error` only when its own time budget ran out or the
  agent was stopping mid-run; nothing from that run is authoritative.
- `images[].variant`: the image's CPU variant (`"v7"` for `arch: "arm"`,
  `"v8"` for `arm64`), omitted when the image declares none (usual on
  amd64). CVE matching treats (os, arch, variant) as the platform.
- Within the Docker block's 30s budget the single-call collectors
  (engine, networks, swarm_services) run before the per-object inspects
  of containers and images, so a very large host can only make those
  last two time out.
- `mounts[].source` is set only for `type: "bind"`, where it is a host
  path, so the dashboard can flag e.g. the Docker socket or `/`
  bind-mounted into a container.
- `engine.image_store` is `"containerd"` (containerd image store; then
  `storage_driver` is the snapshotter, e.g. `overlayfs`) or
  `"graphdriver"` (classic store; e.g. `overlay2`). `swarm.cluster_id` is
  absent on workers (the engine doesn't tell them), so the server takes
  it from a manager's push. `swarm_services[].replicas` is sent only for
  `replicated` services (0 = scaled to zero). Caps: 2000 containers / images, 500 networks, 1000
  Swarm services, plus per-item caps (ports, mounts, layers…); hitting
  any of them, top-level or per-item, flags that collector `truncated`.
- `image` is the reference as configured (a tag can move); `image_id` is
  what the container actually runs, and the key for future image CVE
  matching. `layers` are the image's layer diff IDs.
- Swarm: every node reports its own task containers (with
  `com.docker.swarm.*` labels); only managers report `swarm_services`.
  The server joins them by `cluster_id` / `node_id`. Ingress-published
  ports exist only in `swarm_services`; on each node the listener is
  owned by `dockerd`.

**Server storage** (migration `0013_docker`, `server/internal/ingest/docker.go`,
DOMAIN_MODEL.md §4.5 "Docker"). The block is decoded on its own, so a
malformed one is logged and dropped without failing the push. Each
section is applied only when its collector is `ok` (an absent member
then means empty); `error`, `skipped` or missing leaves what is stored
untouched, and payloads without a `collectors` map never carry Docker
data. `truncated` (or a server cap) makes a section additive.

| Section | Stored in | Keyed by |
|---|---|---|
| `containers` | `host_containers` ranges, kind `containers:docker` | host, container id |
| `images` | `host_images` ranges, kind `images:docker`; content in `container_images` | host, image id; content by (image id, os, arch, variant) |
| `engine`, `swarm` | `host_docker` (current state) | host |
| `networks` | `host_docker.networks` jsonb (current state) | host |
| `swarm_services` | `swarm_services` ranges + `swarm_clusters` bookkeeping | user, cluster id, service id |

- A partial entry (`inspect_error`) keeps its range open and keeps the
  inspect-derived fields of the range before it (for containers: ports,
  networks, network mode, privileged, restart policy, mounts, started
  at; for images: the platform). Fields sent on a partial entry beyond
  the list fields are ignored.
- Image content is keyed by platform as well as id: on the containerd
  image store the id is the image index digest, shared by every
  platform. Partial images aren't interned.
- `swarm_services` is applied only when `docker_engine` is also `ok` and
  reports `swarm.state: "active"`, `role: "manager"` and a `cluster_id`.
  A service missing from such a push (not truncated) is closed, whichever
  manager of the cluster sent it. A locked manager keeps its last known
  node / cluster / role in `host_docker`.
- The server re-applies the bind-only rule for mount sources and bounds
  sizes, but doesn't re-filter label keys (the agent's allowlist is the
  gate).

### Other fields

`reboot_required` / `reboot_required_packages` come from two signals,
and the optional `reboot_required_source` (`"flag_file"` or `"kernel"`,
omitted by older agents; the server doesn't store it) says which one
decided:

- **The flag file** `/run/reboot-required{,.pkgs}`, read only when the
  host's `/run` is visible: bare metal, remote (SSH) targets, and a
  recursive host mount. The container deployment deliberately doesn't
  mount `/run` (its tmpfs holds the host's control sockets); the agent
  tells by device (`/host/run` on the same device as `/host` means the
  tmpfs isn't there, whatever stale directories the root filesystem has
  under it). When visible, it decides (`flag_file`); a missing file is
  the normal "no reboot pending". The agent reads `/run` directly, not
  `/var/run`, which is an absolute symlink to `/run` on modern hosts and
  would resolve inside the agent's own container.
- **The kernel**: a reboot is pending when dpkg has a newer
  `linux-image-[unsigned-]<release>` package of the running kernel's
  flavour (e.g. `generic`) installed than the running one
  (`/proc/sys/kernel/osrelease`), by Debian version ordering. The newer
  kernel packages go in `reboot_required_packages`. It decides when the
  flag file isn't visible, and is OR-ed in when it is (`kernel` is then
  the source only when the flag file said no).

When the flag file isn't visible and the kernel can't decide (the
running kernel isn't a dpkg-installed one, or there's no package
inventory), `reboot_required` is `skipped` with a reason starting
"pending reboot unknown", never a false "no". The kernel signal covers
kernels only: a pending reboot flagged for another package (libc6, dbus)
shows only where the flag file is visible.

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
itself**, or anyone can spoof their recorded source IP. It matters most
for the deferred external port scanner, which would use it to target
only an enrolled agent's own IP ([decisions/port-exposure.md](decisions/port-exposure.md)).

## 3. Credential rotation

Agent-initiated; the server never pushes a secret or makes the agent run
anything, it only asks through the push response header.

```
POST /v1/agent/rotate
X-Agent-ID: <agent_id>
Authorization: Bearer <agent_secret>
```

→ `200 OK`, same shape as enrollment:

```
{ "agent_id": "<uuid>", "agent_secret": "<new random>" }
```

`401` for a wrong or expired secret, an unknown agent, or a revoked agent.

When the server asks (`X-Upkeep-Rotate-Credentials: 1` on a push):

- the dashboard's "Rotate credentials" set
  `agent_credentials.rotate_requested_at` (cleared by the rotation);
- the secret is older than `SW_CREDENTIAL_MAX_AGE` (API env, default
  `2160h` = 90 days, `0` disables): periodic rotation;
- the push authenticated with the **previous** secret (the agent lost the
  new one, see below).

Server side (`ingest.Handler.Rotate`, `store.RotateAgentCredential`, row
locked): if the caller used the current secret, it becomes the previous
one, valid until `now + SW_CREDENTIAL_ROTATION_GRACE` (default `1h`); if
the caller used the previous secret (still in its window), the previous
secret and its original expiry are kept, so repeated rotations never
extend it, and the lost secret is replaced. Only hashes are stored
(`previous_secret_hash`, `previous_expires_at`). The first push
authenticated with the new secret ends the window early
(`ConfirmRotation`), so an old secret normally dies within one push
interval. The worker's hourly `credential_cleanup` job clears expired
previous hashes (and deletes expired enrollment tokens).

Agent side (`agent/cmd/agent/credentials.go`): after a push cycle that
got the header, call `/v1/agent/rotate`, write the new secret to
`credentials.json` atomically, and only then use it. If writing fails,
the new secret is discarded and the old one kept (disk and memory never
disagree); the server keeps accepting the old one for the window and keeps
asking, so the next cycle retries.

Crash between receiving and persisting the new secret: the restarted agent
pushes with the old secret, is accepted (grace window) and told to rotate
again; it rotates with the old secret and persists the result. After the
window the old secret is refused on every endpoint (`401`); the agent then
needs a new enrollment, like a revoked one. Verified end to end with a
real agent container (see the PR for the log).

## 4. Remote targets

An agent collects its own machine (`host.ref: "local"`) and any remote
hosts added in the dashboard ("Add host" → "Reach it from an existing
agent"; `mgmt_add_remote_host`, migration 0012). The server never
connects to the agent or to the remote hosts: the agent pulls its target
list and reports how reaching each one went. Only `ssh` is implemented;
`winrm` is reserved.

### Target list

```
GET /v1/agent/config
X-Agent-ID: <agent_id>
Authorization: Bearer <agent_secret>
If-None-Match: "<etag from the last 200>"      (optional)
```

→ `200 OK` with an `ETag`, or `304 Not Modified` when nothing changed:

```jsonc
{
  "version": "3f1c…",
  "targets": [
    { "ref": "<host uuid>", "mode": "ssh", "address": "10.0.0.12", "port": 22,
      "username": "upkeep",
      "host_key": "ssh-ed25519 AAAA…" }   // "" until the user confirmed one
  ]
}
```

The agent polls every minute (`configPollInterval`), so a new host, or a
host key the user just confirmed, is acted on within a minute. A `404`
means a server that predates remote targets: the agent stops asking and
collects its own machine only.

### Status report

```
POST /v1/agent/status
X-Agent-ID / Authorization as above

{ "ssh_public_key": "ssh-ed25519 AAAA… upkeep-agent",
  "targets": [ { "ref": "<host uuid>", "error_code": "host_key_unconfirmed",
                 "error": "…", "host_key": "ssh-ed25519 AAAA…" } ] }
```

→ `204`. Sent once at startup (so the dashboard can show the agent's
public key and offer the agent as a remote collector: `agents.ssh_public_key`
set) and after every round of target attempts. `error_code` is `""` for a
target that was reached and collected, else one of `host_key_unconfirmed`,
`host_key_mismatch`, `auth_failed`, `unreachable`, `sftp_failed`,
`push_failed` (stored in `agent_hosts.last_error_code`, with `error` in
`last_error` and the time in `last_attempt_at`). Keys are validated
(`server/internal/sshkey`: known type, base64 blob naming the same type)
and stored without comments; an invalid key or unknown code rejects the
report with `400`.

Host keys: a presented key that differs from the confirmed `host_key`
(or with none confirmed) is stored as `host_key_pending` for the user to
confirm (`mgmt_confirm_host_key`, which takes the key the user was shown
and refuses if a different one is pending by then). A host-key error for
a key that is already confirmed is a stale report from a config fetched
before the confirmation and only records the attempt.

### Collection

A successful collection is an ordinary `POST /v1/snapshots` whose
`host.ref` is the target's ref; the server maps it onto the pre-created
host (`resolveRemoteHost`), refusing unknown refs with `422`. Rules on
the agent (`agent/cmd/agent/remote.go`, `agent/internal/target/ssh.go`):

- **No command execution.** The agent opens the `sftp` subsystem and
  reads files; it never requests a shell or `exec`. The dashboard's setup
  lines pin the key to `restrict,command="/usr/lib/openssh/sftp-server -R"`,
  so the remote side enforces read-only SFTP too (verified: with that
  line, the key can neither run a command nor write a file).
- **Pinned host keys, confirmed by the user.** With no confirmed key the
  agent only completes the key exchange, captures the key and aborts
  before authenticating, then reports `host_key_unconfirmed`. With one, it
  negotiates only that key's algorithm and refuses any other key
  (`host_key_mismatch`, reporting the presented key).
- **The private key stays on the agent**: `SW_DATA_DIR/ssh/id_ed25519`
  (generated on first start, 0600), or an operator-supplied file at
  `SW_SSH_KEY_FILE` (never generated or overwritten). Only the public half
  is sent.
- **Facts.** The same collectors run against the SFTP filesystem:
  packages, OS, identity (machine-id, hostname), services, users,
  unattended-upgrades, reboot-required, and kernel release / uptime / arch
  from single `/proc` files (`target.ProcFiles`). Listeners, process
  → unit mapping and deleted libraries need to walk live process state
  (`target.LiveProc`) and are reported `skipped`; so is the public IP
  lookup, which would describe the agent's network. The Docker
  collectors (planned) are `skipped` too: SFTP can't reach the remote
  Docker socket ([decisions/docker-collection.md](decisions/docker-collection.md)).
- **Scheduling.** Each target is collected every push interval. A failed
  attempt is retried after 1m, doubling up to the push interval, so a
  host being set up is retried quickly without an SSH login every minute
  forever (which would also trip fail2ban-style lockouts).
- **Port scanning.** A remote host's pushes come from the agent's IP, so
  `snapshots.source_ip` says nothing about the host. Remote hosts are not
  eligible for the external port scan, if it is built (DOMAIN_MODEL.md
  Q5; deferred to Phase 2+).

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

- Port-exposure classification ([tasks/phase-1-6-docker-exposure.md](tasks/phase-1-6-docker-exposure.md)) — see
  `TODO(phase 1, exposure)` in `handler.go`. Like vulnerability matching,
  it is enqueued per snapshot, not run inline in the request handler.
- No agent self-update.
