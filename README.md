# security-whatnot

Lightweight security monitoring for small developers self-hosting on VPSes
(Hetzner, OVH, DigitalOcean) via Dokploy or Coolify. Tells you the handful
of things on your servers that actually matter:

1. **Security updates** — installed packages with known CVEs, prioritized
   by real-world exploitability (CISA KEV, FIRST EPSS), not raw CVSS.
2. **Open ports** — what's listening on the host vs. what's actually
   reachable from the internet.
3. **Patched but not fixed** — reboot required, or services still running
   old library versions after an upgrade.
4. *(Phase 2)* Container image vulnerabilities for Docker workloads.

## Architecture

```
agent/   Go, single static binary. Read-only, outbound-only. Collects
         packages, listening sockets, OS release, reboot state; pushes
         a versioned JSON snapshot over HTTPS. No inbound ports, no
         remote command execution.

server/  Go. Agent enrollment + snapshot ingest today. Vulnerability
         matching, external port-exposure scanning, and alert dispatch
         land here as background workers (see roadmap below).

web/     Next.js (App Router) + Auth.js. Marketing, auth, dashboard.
         Reads Postgres directly for display (Server Components) —
         it does not proxy dashboard reads through the Go API. See
         "Who owns what" below for the write-ownership split.

migrations/  SQL migrations (golang-migrate format), shared by both
             services — this is the actual contract between them.
```

### Why Go for ingest, not Next.js API routes

The agent protocol needs strict schema versioning and a per-agent bearer
credential, and shares its wire format with the agent binary. Ingestion,
vuln matching, KEV/EPSS enrichment, and external scanning are background
long-running/CPU-bound jobs — a better fit for a persistent Go process
with real workers than serverless-shaped Next.js routes.

### Who owns what (avoiding split-brain writes)

Two codebases touch the same Postgres schema, so ownership is drawn by
**who needs to enforce business logic**, not by "which language talks to
the DB":

- **Go owns writes to:** `snapshots`, `snapshot_packages`,
  `listening_sockets`, `vulnerabilities`, `findings`, `alert_events`
  (everything produced by ingestion/matching/scanning/alerting).
- **Next.js owns writes to:** `users`, `enrollment_tokens`,
  `alert_rules`, `notification_channels` (plain user-settings CRUD).
- **Both read anything directly from Postgres.** No caching layer sits
  in front of these reads yet. If one is added later (e.g. Next.js
  `"use cache"` + `cacheTag` on a findings page), it must be invalidated
  via an on-demand revalidation call from whichever side wrote the row
  — Next.js's Data Cache never learns about a write made by the Go
  process on its own. This is the standard pattern for external writers
  invalidating Next.js's cache (the same shape as a CMS webhook), not a
  workaround.

### Protocol (agent ↔ server)

1. **Enrollment**: dashboard generates a one-time token
   (`enrollment_tokens`, 1-hour expiry). Agent calls
   `POST /v1/enroll {enrollment_token, hostname}`, gets back
   `{agent_id, agent_secret}`. The token is deleted atomically on use.
   Only a SHA-256 hash of `agent_secret` is ever stored server-side.
2. **Snapshot push**: agent calls `POST /v1/snapshots` with
   `X-Agent-ID: <agent_id>` and `Authorization: Bearer <agent_secret>`,
   body is a `schema_version`-tagged JSON snapshot (packages, listening
   sockets, OS release, reboot state). Every historical snapshot is kept
   (not upserted) so drift and findings history stay auditable.
3. **Versioning**: additive fields don't need a bump. A breaking shape
   change bumps `schema_version` and the server's
   `MinSupportedSchemaVersion`.

## Local development

```sh
docker compose -f docker-compose.dev.yml up --build
```

This starts Postgres, runs migrations, then the Go API (`:8080`) and the
Next.js app (`:3000`). Copy `web/.env.example` to `web/.env.local` for
`next dev` outside Docker.

To run your own VPS as a monitored host against local dev, use
`agent/docker-compose.example.yml` with `SW_SERVER_URL` pointed at your
tunneled/public dev API, and an enrollment token from the dashboard.

## Production deployment (Dokploy on your own box)

Use the root `docker-compose.yml` as a Dokploy compose app. Required env
vars: `POSTGRES_PASSWORD`, `PUBLIC_API_URL`, `PUBLIC_WEB_URL`,
`AUTH_SECRET` (generate with `openssl rand -base64 32`). Point Dokploy's
domains at the `web` service (port 3000) and `api` service (port 8080).

Then deploy `agent/docker-compose.example.yml` on each host you want
monitored, with `SW_SERVER_URL` set to your platform's public API URL and
an enrollment token generated from the dashboard's "Add host" button.

## MVP roadmap (~4-6 weeks)

1. ✅ Agent collectors (packages, sockets, OS release, reboot) +
   enrollment + ingest + schema.
2. OSV Debian/Ubuntu sync + dpkg-version-comparison matching + CISA KEV /
   FIRST EPSS enrichment → `vulnerabilities` table.
3. Findings generation from snapshots + minimal dashboard (host list,
   findings list, severity ranked by KEV/EPSS first).
4. External port-exposure scanning (scan only IPs verified as an
   enrolled agent's own connection source, rate-limited) + webhook/email
   alerting with dedup (`alert_events`, open/resolved).
5. Polish, docs, digest-mode alerts, Discord/Slack/ntfy channels.

**Phase 2+**: container image vulnerabilities for Docker workloads, RHEL/
Alpine package collectors, SMS notifications, billing.

## Biggest risks

- **Version-matching correctness**: Debian/Ubuntu backport suffixes
  (`~`, `+deb12u1`, etc.) must be compared with real dpkg version
  semantics, not string/semver comparison, or findings will be silently
  wrong in both directions.
- **Alert fatigue**: raw CVSS ranks almost everything "critical." Ranking
  must lead with CISA KEV (actively exploited) and EPSS (predicted
  exploitation probability), with CVSS only as a tiebreaker.
- **Scanning abuse**: the platform must never be usable to port-scan
  arbitrary targets. Only scan an IP that matches an enrolled agent's own
  verified connection source, and rate-limit aggressively.
