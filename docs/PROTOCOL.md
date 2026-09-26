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
  "os": { "id": "ubuntu", "version_id": "22.04", "codename": "jammy" },
  "packages": [
    { "name": "openssl", "version": "3.0.2-0ubuntu1.15", "arch": "amd64" }
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
and findings history stay auditable — see `store.InsertSnapshot`.

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

## Not yet implemented

- Snapshot processing is currently insert-only — see the `TODO(phase 1)`
  in `handler.go`. Vulnerability matching and port-exposure evaluation
  are meant to be enqueued per snapshot once those workers exist, not run
  inline in the request handler.
- No credential rotation endpoint yet (only initial enrollment).
- No agent self-update / version-reporting in the payload yet.
