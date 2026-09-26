# Agent ↔ Server Protocol

The agent is outbound-only: it never opens a listening port, and the
server never connects to it. Everything below is initiated by the agent.

## 1. Enrollment

One-time, per host. The dashboard generates a token (`enrollment_tokens`
table, 1-hour expiry) via the "Add host" button
(`web/src/app/dashboard/actions.ts`).

```
POST /v1/enroll
Content-Type: application/json

{ "enrollment_token": "<token>", "hostname": "my-vps" }
```

→ `200 OK`

```
{ "agent_id": "<uuid>", "agent_secret": "<random>" }
```

The token is deleted atomically on use (`ConsumeEnrollmentToken` in
`server/internal/store/store.go`) so it can't be replayed even if leaked
after use. `agent_secret` is generated with 32 bytes of `crypto/rand`
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
  "host": {
    "ref": "local",
    "os_family": "linux",
    "hostname": "web-1",
    "identity": { "machine_id": "0123456789abcdef0123456789abcdef" }
  },
  "os": { "id": "ubuntu", "version_id": "22.04", "codename": "jammy" },
  "collectors": {
    "os":              { "status": "ok" },
    "host_identity":   { "status": "ok" },
    "deb_packages":    { "status": "ok" },
    "tcp_listeners":   { "status": "ok" },
    "reboot_required": { "status": "ok" },
    "public_ip":       { "status": "ok" }
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
  server should upsert hosts on (DOMAIN_MODEL.md §4.3), so a reinstalled
  agent reattaches to its host. Omitted when unreadable, empty or
  `uninitialized`; `collectors.host_identity` is then `error`.

Snapshots from agents that predate the host block omit it entirely. Treat
those as the authenticating agent's local host.

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
| `os` | `os`, `host.os_family` | always |
| `host_identity` | `host.hostname`, `host.identity` | Linux |
| `deb_packages` | `packages` entries with `ecosystem: "deb"` | Debian-like Linux (`ID` or `ID_LIKE` contains `debian`/`ubuntu`) |
| `tcp_listeners` | `listening_sockets` | Linux with live procfs (local target) |
| `reboot_required` | `reboot_required`, `reboot_required_packages` | Debian-like Linux |
| `public_ip` | `public_ipv4`, `public_ipv6` | local target (best-effort: `ok` with no IPs is normal) |

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

### `packages`

| Field | Meaning |
|---|---|
| `name`, `version`, `arch` | The binary package as installed. |
| `source`, `source_version` | The source package it was built from. Debian/Ubuntu advisories are keyed by source package and version (DOMAIN_MODEL.md §2.5). From dpkg's `Source:` field: absent means the same as the binary; `Source: foo` means source `foo` at the binary's version; `Source: foo (1.2-3)` gives an explicit source version (binNMUs). Always set by this agent; older agents omit both. |
| `ecosystem` | Which package source reported it: `"deb"` (dpkg). Keys `software_versions.ecosystem`. Older agents omit it; treat as `"deb"`. |

Only packages whose dpkg `Status:` state (third word) is exactly
`installed` are sent. `half-installed`, `not-installed`, `config-files`,
`unpacked` and `half-configured` are excluded.

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

Auth: the bearer secret is verified in constant time
(`authn.VerifySecret`) against the hash stored for `X-Agent-ID`. There is
no shared platform-wide credential — each host has its own scoped secret.

The server keeps **every** historical snapshot (not an upsert) so drift
and findings history stay auditable — see `store.InsertSnapshot`. Package
inventory is additionally folded into validity ranges (`host_software`)
in the same transaction; `snapshots.schema_version` stores the payload's
value.

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
- `host`, `collectors` and the package `source` / `source_version` /
  `ecosystem` fields were added **within `schema_version: 1`**. The
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
- No agent self-update / version-reporting in the payload yet.
