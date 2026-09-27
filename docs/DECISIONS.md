# Decisions

A running log of the "why" behind non-obvious choices, so a fresh session
(or future you) doesn't relitigate them without new information. Ordered
roughly by when they were made.

## Ingest API in Go, not Next.js API routes

The agent protocol needs strict schema versioning and a per-agent bearer
credential, and shares its wire shape with the agent binary itself.
Ingestion, vuln matching, KEV/EPSS enrichment, and exposure analysis are
background, long-running/CPU-bound jobs — a persistent Go process with
real workers fits better than serverless-shaped Next.js route handlers.

## Direct Postgres reads from Next.js

Considered: should the dashboard read Postgres directly, or go through
the Go API for everything (including reads)?

**Decided: direct reads**, with write ownership split by table (see
[ARCHITECTURE.md](ARCHITECTURE.md#who-owns-what-avoiding-split-brain-writes)).
Reasoning:

1. No new trust boundary is created — the browser never touches Postgres
   either way; only server-side Next.js code (Server Components, Server
   Actions) would, running in the same private network as the Go API.
2. The Go API's job is agent-protocol + background workers, not general
   CRUD. Dashboard reads (list my hosts, my findings) are plain
   `WHERE user_id = session.user.id` queries — not agent-protocol logic.
3. Building the same CRUD twice (a Go REST surface *and* a typed Next.js
   client for it) is pure overhead for a solo founder, for tables with no
   business logic beyond row ownership.
4. It's the idiomatic Next.js App Router pattern (Server Components
   querying a DB directly via `pg`/Drizzle/Prisma), not a shortcut.

**Caching implication** (raised explicitly — worth preserving): Next.js's
Data Cache only wraps `fetch()`, not raw `pg.query()` calls, so as built
there is no cache to go stale. If caching is added later on a
Go-written table, the correct long-term fix is **not** routing reads
through Go — it's Go calling an on-demand revalidation endpoint in
Next.js after it writes (`POST /api/revalidate?tag=...`), the same
pattern Next.js recommends for any external writer (CMS webhooks, etc.).
This is a durable production pattern, not a stopgap. The real argument
*for* full API-mediation would be a different one — single-writer
enforcement of business rules — which is already handled by the
write-ownership split without needing to route reads through Go too.

## Auth: self-hosted Auth.js, not a managed vendor (Clerk/Auth0)

Fits the project's self-hosted, no-vendor-sprawl pitch — a security
monitoring tool that itself depends on a third-party auth vendor is a
harder sell. Cost: we own session/password security (bcrypt cost 12,
`AUTH_SECRET`-signed JWT sessions), rather than offloading it.

## Single-user tenancy for MVP (no orgs/teams)

`hosts.user_id` is a direct FK, not `hosts.org_id`. Simplest schema for
launch; adding an organization layer later is a straightforward
migration (`users` → `organizations` → `hosts`) if team customers show
up, and not worth the upfront complexity for a solo founder before
there's demand.

## Billing deferred

Ship free during beta; no Stripe integration yet. Keeps MVP scope inside
the 4-6 week target. `alert_rules`/`notification_channels` have no plan
gating fields — add them when billing is actually built, don't
pre-guess the shape.

## Email notifier: SMTP settings per channel, not platform config

Considered: one platform-wide SMTP server (operator config, e.g.
`SW_SMTP_*`) that every user's email channel sends through, versus each
channel carrying its own SMTP server.

**Decided: per channel.** The user enters host, port, security,
username/password and from/to in the channel form, like webhook and ntfy
settings; there is no platform SMTP config. Reasoning: self-hosters
already have a mail provider or relay, and mail sent from their own
domain and account lands better than mail from a shared sender; the
platform doesn't take on deliverability, sender-domain verification or
abuse handling for everyone's alerts; and it keeps the notifier framework
uniform (config + secrets per channel, no special-cased type). Cost: each
user has to configure SMTP themselves. A platform default could be added
later as an optional fallback without changing the channel schema.

Security choices that go with it: STARTTLS is the default and is
required when selected; certificates are always verified; credentials are
never sent over a connection without TLS unless the channel explicitly
turns on "Allow insecure authentication" (default off). Connections go
through `netguard`'s SMTP policy (ports 25/465/587/2525, public addresses
only) — see [ARCHITECTURE.md § Email (SMTP) channel](ARCHITECTURE.md#email-smtp-channel).

## Port exposure: host-side analysis, not an external scanner (MVP)

Considered (2026-09-27): a River job in the worker that TCP-probes an
agent's server-observed `snapshots.source_ip` on its listening ports,
versus deriving exposure from what the agent can read on the host.

**Decided: host-side analysis for the MVP; the external scanner is
deferred to Phase 2+.** The scanner's vantage point is the platform box,
not the internet. For self-hosters that is often wrong: agents pushing
over a private network (vSwitch, VPC, Tailscale/WireGuard) give a
private `source_ip`; firewall allowlists commonly let the user's own
admin box through, so "open from here" isn't "open to everyone"; an agent
on the platform box itself can't be probed from outside. A result that
is sometimes misleading costs trust in every other alert. It also brings
real infrastructure (scan jobs, rate limits, abuse controls) and the
"platform used to scan arbitrary targets" risk.

Instead: classify each listener from the host's own facts, namely
listeners, ufw configuration, and Docker published ports (TASKS.md
Phase 1.6). **ufw alone is not enough**: Docker publishes ports through
its own iptables rules, which are evaluated before ufw's, so
`ufw deny 5432` doesn't protect `ports: "5432:5432"`. That is the most
likely way a self-hoster's database becomes public, so Docker data is a
prerequisite, not an extra. The wording is "not protected by the host
firewall", never "public": provider firewalls (Hetzner Cloud and
similar) are invisible to the agent, and we expect users to run a host
firewall regardless. The scanner can come back later as a second
opinion, with the constraints in TASKS.md Phase 2+.

## Docker collection: Engine API from the agent, opt-in socket mount

Considered (2026-09-27): (1) the Docker Engine API over
`/var/run/docker.sock`; (2) reading Docker's on-disk state under
`/var/lib/docker/containers/<id>/{config.v2,hostconfig}.json` through
the existing `/:/host:ro` mount, like the systemd collector avoids D-Bus.

**Decided: (1).** On-disk state can't cover the scope we want: Swarm
service definitions (published ingress ports, replicas) live only in
managers' encrypted Raft store; image metadata is in different places for
the classic graphdriver store and the containerd image store
(increasingly the default for new installs), the latter in containerd's
locked metadata database; rootless Docker, a moved `data-root` and
Podman each need special handling. The API is documented and versioned,
covers containers, images, networks, Swarm services/tasks/nodes, and
Podman serves a compatible one. We support Docker and Swarm generically,
not Dokploy or Coolify specifically.

Access to the API is root on the host (anything that can talk to it can
start a privileged container); a `:ro` mount of a socket doesn't
restrict it, and there is no read-only mode for the socket. Two ways to
limit that were rejected:

- **An allowlisting proxy sidecar** holding the socket, with no network,
  serving read endpoints to the agent. Rejected: the realistic way the
  agent gets compromised is a malicious release (stolen publish token,
  CI or dependency compromise), and the proxy ships from the same
  pipeline, so it falls with the agent. Against a compromised platform
  server steering agents, a client that has no code path for anything
  but fixed GETs protects just as well, since the server can only
  trigger what the agent's code does. What remains is arbitrary code
  execution inside a Go binary, the least likely case. Not worth the
  extra moving part.
- **A native (systemd) agent** as an unprivileged user with
  `CAP_DAC_READ_SEARCH`: tested to read every file yet be denied
  `connect()` on `docker.sock` (connecting needs write permission on the
  socket). Rejected for UX: users deploy everything through a compose
  file in their panel, and the socket still needs the privileged
  `docker` group for Docker data.

So: **the socket is mounted into the agent container, opt-in**, and the
boundary is the agent's own code: a hand-written client that can only
send a fixed list of GETs (not "GET-only": `GET
/containers/{id}/archive`, `/export`, `/images/{id}/get`, `/logs` and
`/configs/{id}` all leak data), plus wire types that only carry declared
fields and allowlisted label prefixes, because env and labels hold
secrets. This is the same trust model as other monitoring agents that
mount the socket (Datadog, Netdata, cAdvisor), and we say so plainly:
with Docker enabled the agent is root-equivalent and "read-only" means
"only makes read calls, by design". The effort goes into release
supply chain instead (signed images, SBOM and provenance, versioned tags
rather than `:latest`, scoped publish tokens; TASKS.md), which protects
every host whether or not Docker is enabled.

Found while deciding this: the current `/:/host:ro` mount is recursive,
so `/host/run/docker.sock` is already reachable, and was shown to allow
`POST /containers/create` under the agent's exact hardening. The agent
code never uses it, but it means opting out of Docker isn't real until
that mount is fixed (TASKS.md Phase 1.6).

## Next.js deploys as a Docker standalone image, not on Vercel

The whole pitch is self-hosting on your own VPS via Dokploy/Coolify.
`next.config.ts` sets `output: "standalone"` so the production image
only ships the traced runtime deps, not full `node_modules`
(`web/Dockerfile`, multi-stage: deps → build → runtime).

## Package manager: Bun (migrated from npm)

`web/` originally scaffolded with npm (`create-next-app --use-npm`),
migrated to Bun on request. `bun.lock` is the lockfile; Docker build/deps
stages use `oven/bun:1.4.2-alpine`, but the **runtime** stage stays on
plain `node:22`→`24-alpine` running `node server.js` — Next.js
standalone's entrypoint is plain Node, so there's no reason to ship Bun
into the runtime image just to run it.

## Linting/formatting: oxlint + oxfmt (migrated from ESLint)

Replaced ESLint/`eslint-config-next` with oxlint (rules: react,
typescript, import, nextjs, unicorn, correctness) and oxfmt. Zero real
lint findings at migration time; oxfmt only reformatted cosmetics.

## Version policy

Dependencies/base images were bumped to whatever was verified as
current-latest as of 2026-09-26 (Go 1.27.1 toolchain, Node 24-alpine,
Postgres 18.6-alpine, golang-migrate v4.20.1, TypeScript 7/tsgo, etc.) —
checked against live sources (registries, Docker Hub, nodejs.org), not
assumed from training data. **This will drift.** Re-audit periodically
rather than assuming pins in this repo stay current; don't trust a
memory or doc snapshot of "latest" over checking again.

One deliberate non-bump: `server/Dockerfile`'s runtime stage stays on
`alpine:3.20` — out of scope of the last audit pass, not yet re-checked.

## Postgres 18's data directory mount

Postgres 18's official image switched to a pg_ctlcluster-style layout
and expects a single volume mount at `/var/lib/postgresql` (not
`/var/lib/postgresql/data` as in older images) — mounting at the old path
causes the container to refuse to start. Both compose files mount
`pgdata:/var/lib/postgresql` accordingly. If you ever pin back to an
older Postgres major, check whether this needs reverting.
