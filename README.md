# security-whatnot

Lightweight security monitoring for small developers self-hosting on VPSes
(Hetzner, OVH, DigitalOcean) via Dokploy or Coolify. Not Wazuh, not
Qualys — just the handful of things on your servers that actually matter:

1. **Security updates** — installed packages with known CVEs, prioritized
   by real-world exploitability (CISA KEV, FIRST EPSS), not raw CVSS.
2. **Open ports** — what's listening on the host vs. what's actually
   reachable from the internet ("port 5432 just became public").
3. **Patched but not fixed** — reboot required, or services still running
   old library versions after an upgrade.
4. *(Phase 2)* Container image vulnerabilities for Docker workloads.

**Status**: early scaffold. The agent→ingest pipeline (enrollment, fact
collection, snapshot storage) and the dashboard's auth/host-list flow
work end to end. The actual vulnerability-matching and alerting pipeline
— the core value prop — isn't built yet. See
**[docs/TASKS.md](docs/TASKS.md)** for exactly what's done vs. outstanding
before picking up new work.

## Repo layout

```
agent/       Go, single static binary. Read-only, outbound-only host
             fact collector (packages, listening sockets, OS release,
             reboot state). No inbound ports, no remote command execution.
server/      Go. Agent enrollment + snapshot ingest today; vulnerability
             matching, port scanning, and alert dispatch land here.
web/         Next.js (App Router) + Bun + Auth.js. Marketing, auth,
             dashboard. Reads Postgres directly (see docs/DECISIONS.md).
migrations/  SQL migrations (golang-migrate format) — the actual schema
             contract shared by server/ and web/.
docs/        Architecture, protocol spec, decision log, task tracker.
```

For anything beyond a quick start, read:

- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — components, data
  flow, the Go/Next.js write-ownership split, deployment shapes.
- **[docs/PROTOCOL.md](docs/PROTOCOL.md)** — the agent↔server wire
  format, auth, and versioning policy.
- **[docs/DECISIONS.md](docs/DECISIONS.md)** — why things are built this
  way (direct Postgres reads, self-hosted auth, package manager, version
  pinning policy, etc.) — read before relitigating a past call.
- **[docs/TASKS.md](docs/TASKS.md)** — done vs. to-do, kept current.

## Local development

```sh
docker compose -f docker-compose.dev.yml up --build
```

This starts Postgres, runs migrations, then the Go API (`:8080`) and the
Next.js app (`:3000`). Zero setup — dev credentials are hardcoded in that
file on purpose. Copy `web/.env.example` to `web/.env.local` if you want
to run `bun dev` outside Docker.

To test against a real host, deploy `agent/docker-compose.example.yml` on
a VPS with `SW_SERVER_URL` pointed at your dev API (tunneled or public)
and an enrollment token from the dashboard's "Add host" button.

## Production deployment (Dokploy on your own box)

```sh
cp .env.example .env   # then fill in real values, see below
docker compose up --build -d
```

`docker-compose.yml` is the production stack (Postgres + migrate + api +
web), meant to run once on your own box via Dokploy. Required vars (see
`.env.example`): `POSTGRES_PASSWORD`, `PUBLIC_API_URL`, `PUBLIC_WEB_URL`,
`AUTH_SECRET` (generate with `openssl rand -base64 32`). Point Dokploy's
domains at the `web` service (port 3000) and `api` service (port 8080).

Then deploy `agent/docker-compose.example.yml` on each host you want
monitored, with `SW_SERVER_URL` set to your platform's public API URL.

## Roadmap

See [docs/TASKS.md](docs/TASKS.md) for the actionable breakdown. At a
glance, the phases:

1. ✅ Agent collectors + enrollment + ingest + schema.
2. ✅ OSV Debian/Ubuntu sync + dpkg-version-comparison matching + CISA KEV /
   FIRST EPSS enrichment → findings.
3. ✅ Dashboard findings UI.
4. External port-exposure scanning + webhook, ntfy and email (SMTP)
   alerting with dedup and digest mode (Slack/Discord integrations
   deferred).
5. Polish, tests, CI.

**Phase 2+** (explicitly deferred): container image vulnerabilities,
RHEL/Alpine collectors, Slack/Discord notifiers, SMS, billing,
multi-tenant orgs.

**Non-goals**: auto-patching, remote command execution, compliance
reporting (SOC2/CIS), Windows/macOS support, log analysis/SIEM.

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
