# security-whatnot

Lightweight security monitoring for small developers self-hosting on VPSes
(Hetzner, OVH, DigitalOcean) via Dokploy or Coolify. Not Wazuh, not
Qualys — just the handful of things on your servers that actually matter:

1. **Security updates** — installed packages with known CVEs, prioritized
   by real-world exploitability (CISA KEV, FIRST EPSS), not raw CVSS.
2. **Open ports** — what's listening on the host, and whether the host
   firewall actually covers it ("port 5432 is published by Docker, and
   ufw doesn't apply to it").
3. **Patched but not fixed** — reboot required, or services still running
   old library versions after an upgrade.
4. **Docker inventory** — containers, images and Swarm services per host;
   *(Phase 2)* vulnerabilities in those images.

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
             matching, exposure analysis, and alert dispatch land here.
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

### Docker collection (optional)

The agent can inventory a host's Docker containers, images, networks and
Swarm services. It's off by default: enable it by mounting the Docker
socket into the agent (uncomment the line in
`agent/docker-compose.example.yml`, or tick "Collect Docker containers
and images" in the dashboard's Register agent dialog):

```yaml
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

What that grants: access to the Docker socket is full Docker API access,
which is **root-equivalent on the host** (anything that can talk to it
can start a privileged container). A socket has no read-only mode, and
`:ro` on the mount doesn't limit it. The agent only makes read calls, by
design: ping, version, info, container list/inspect, image
list/inspect, network list, and on Swarm managers service/task/node list.
It never calls logs, exec, file export, secrets or configs, never changes
state, and never sends environment variables
([docs/DECISIONS.md](docs/DECISIONS.md) "Docker collection").

The container side is `/var/run/docker.sock` unless you set
`SW_DOCKER_SOCKET`. On the host side, mount the socket your engine uses:

| Engine | Host socket |
|---|---|
| Docker | `/var/run/docker.sock` |
| Rootless Docker | `$XDG_RUNTIME_DIR/docker.sock`, e.g. `/run/user/1000/docker.sock` |
| Podman (rootful) | `/run/podman/podman.sock` after `systemctl enable --now podman.socket` |
| Podman (rootless) | `$XDG_RUNTIME_DIR/podman/podman.sock` after `systemctl --user enable --now podman.socket` |

The agent runs as root (uid 0) in its container but with all
capabilities dropped, so it can't bypass file permissions: it connects
because root owns the usual rootful sockets. If the socket you mount is
owned by another user (a rootless socket while the agent runs under a
rootful engine), add the socket's group id (`stat -c %g <socket>`) with
`group_add` in compose or `--group-add` on `docker run`.

Docker is only collected on hosts with their own agent. Hosts reached
over SSH from another agent ("Add host" → "Reach it from an existing
agent") are read over SFTP, which can't reach the socket, and also don't
report listening ports, port exposure, processes needing a restart or
the public IP.

## Roadmap

See [docs/TASKS.md](docs/TASKS.md) for the actionable breakdown. At a
glance, the phases:

1. ✅ Agent collectors + enrollment + ingest + schema.
2. ✅ OSV Debian/Ubuntu sync + dpkg-version-comparison matching + CISA KEV /
   FIRST EPSS enrichment → findings.
3. ✅ Dashboard findings UI.
4. ✅ Webhook, ntfy and email (SMTP) alerting with dedup and digest mode
   (Slack/Discord integrations deferred).
5. Docker inventory (containers, images, Swarm) + host-side port
   exposure (listeners × ufw × Docker published ports) with alerts.
6. Polish, tests, CI.

**Phase 2+** (explicitly deferred): container image vulnerabilities,
external port-exposure scanning, RHEL/Alpine collectors, Slack/Discord
notifiers, SMS, billing, multi-tenant orgs.

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
- **False reassurance on exposure**: Docker-published ports bypass ufw,
  so "ufw is on" says nothing about a container's ports. Exposure must
  combine listeners, firewall config and Docker's published ports, and
  say "not protected by the host firewall" rather than guess "public".
- **Docker socket = root**: with Docker collection enabled (opt-in),
  the agent is root-equivalent on that host. Its code only makes a
  fixed list of reads, and releases must be signed and
  pinned, since a malicious release is the realistic threat (see
  docs/DECISIONS.md).
