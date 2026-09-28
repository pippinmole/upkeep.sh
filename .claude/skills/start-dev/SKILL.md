---
name: start-dev
description: Starts the security-whatnot local dev environment (Postgres + API in Docker, Next.js dev server natively) and/or spins up a real test agent against it, on Windows (via WSL2) or macOS (via a real-Ubuntu Docker image). Use this whenever the user asks to start/run/spin up the dev environment or dev stack for this project, wants to test the agent locally, register/enroll a test agent, verify a change to the agent or ingest pipeline end-to-end, or debug why a host isn't reporting in — even if they just say "fire up the dev environment" or "let's test this agent change" without naming Docker, WSL, or any script directly.
---

# start-dev

Two independent jobs, use either or both depending on what's asked:

1. **Start the dev stack** — Postgres, migrations, and the Go API in Docker; the Next.js dev server natively on the host.
2. **Run a real test agent** against that stack, cross-platform (Windows via WSL2, macOS via Docker).

Both are backed by scripts in `scripts/` — read them before running if you want the exact commands, but the summaries below are enough to drive them correctly. Run all scripts from Bash (Git Bash on Windows, the normal shell on macOS) from anywhere in the repo — they resolve the repo root themselves via `git rev-parse --show-toplevel`.

## 1. Starting the dev stack

```
bash .claude/skills/start-dev/scripts/up.sh
```

This brings up `postgres`/`migrate`/`api` via `docker compose -f docker-compose.dev.yml up -d --build` (`--build` so server changes are picked up; without it compose reuses stale images whenever they already exist, and the build cache makes it quick when nothing changed), waits for Postgres to report healthy and the API to answer on `:8080`, creates `web/.env.local` from `web/.env.example` with a freshly generated `AUTH_SECRET` if it doesn't exist yet, runs `bun install`, then execs `bun run dev` in the foreground.

**Why `web` isn't started in Docker**: it used to be, but Turbopack's dev filesystem cache (`experimental.turbopackFileSystemCacheForDev`, on by default since Next 16.1) was found to serve stale compiled output indefinitely — surviving even a full dev-server restart — both under a Docker bind mount and running natively. It's now disabled in `web/next.config.ts` with a comment explaining why; don't re-enable it without first confirming edits still hot-reload. Because of this history, `web` was also removed entirely from `docker-compose.dev.yml` in favor of running it natively, which sidesteps a *separate*, since-superseded theory about Docker bind-mount file watching that turned out not to be the real cause. If you're asked to "just run it in Docker like before," push back gently and point at this — it was tried and is why things are the way they are now, not an oversight.

Since `up.sh` ends by `exec`-ing the dev server, it blocks in the foreground. Run it with the Bash tool's `run_in_background: true` if you need the shell back — the dev server logs (including Turbopack recompiles) land in that background task's output.

If you only need Postgres/API up (e.g. to run a test agent) without touching the web dev server, just run `docker compose -f docker-compose.dev.yml up -d --build` directly instead of the whole script.

## 2. Running a test agent

The real agent (`agent/`) is a small Go binary that expects to run either as a container with the real host's filesystem bind-mounted at `/host` (production shape, see `agent/docker-compose.example.yml`), or — for this local-testing purpose — against some filesystem that genuinely has `/etc/os-release` and a dpkg database, symlinked to `/host`. Neither Windows nor a bare macOS Docker Desktop VM has that natively, so the two platforms take different but parallel approaches:

**Windows** — via WSL2, which has a real Ubuntu/Debian filesystem to test against:

```
bash .claude/skills/start-dev/scripts/test-agent-windows.sh [wsl-distro-name] [interval]
```

Defaults: distro `Ubuntu` (check installed distros with `wsl -l -v` if the user has a different one — it must be Debian/Ubuntu-family for the package collector to find anything), interval `30s` (short, for fast test feedback — real deployments use something like `15m`).

This builds the agent image fresh (so it picks up local source changes), extracts the static binary, copies it into WSL, ensures a `/host -> /` symlink exists there (one-time per distro, the script checks first), mints a fresh one-time enrollment token by inserting directly into the `enrollment_tokens` table — this is not a workaround or a bypass, it's the literal same `INSERT` that `web/src/app/dashboard/actions.ts`'s `createEnrollmentToken()` runs server-side when someone clicks "Register agent" in the dashboard — and runs the agent binary against `http://localhost:8080`.

**macOS** (or any Docker host, including native Linux) — via a dedicated Docker image built from a real `ubuntu:22.04` base instead of the production `agent/Dockerfile`'s `FROM scratch`:

```
bash .claude/skills/start-dev/scripts/test-agent-mac.sh [interval]
```

`scripts/test-agent.Dockerfile` builds the agent binary the same way the production Dockerfile does, but lands it in a real Ubuntu image with a baked-in `/host -> /` symlink — so the container has its own genuine dpkg database and `/etc/os-release`, no bind mount needed at all. It runs with normal bridge networking and `SW_SERVER_URL=http://host.docker.internal:8080` (plus `--add-host` for portability to native Linux Docker, where `host.docker.internal` isn't automatic) rather than `--network host`, since host networking isn't reliably supported on Docker Desktop for Mac.

Both scripts print progress as they go and leave the agent running in the foreground, pushing a new snapshot every `interval`. Ctrl-C to stop. Each run mints a brand-new host identity (enrollment always creates a new row — there's no "re-enroll the same host" concept in this codebase yet), so expect a fresh row to show up in `/dashboard/agents` each time you run one of these, not an update to a previous test host.

### Which account the test host lands in

The dashboard only shows a user their own hosts, so the enrollment token must belong to the account you sign in with. Both scripts get the token from `scripts/enroll-token.sh`, which uses `SW_TEST_USER_EMAIL` if set, else the only user if there is exactly one, and otherwise **stops and lists the users** instead of guessing (a `LIMIT 1` used to enroll into a leftover test account, so hosts silently never appeared). Ask the user which account they sign in with, or read it from the dev DB, then run e.g.:

```
SW_TEST_USER_EMAIL=admin@admin.com bash .claude/skills/start-dev/scripts/test-agent-mac.sh
```

### Docker data (macOS script)

`test-agent-mac.sh` mounts the Docker socket read-only by default, so the agent's Docker collectors report Docker Desktop's real containers and images; the Images pages and image vulnerabilities need them. `SW_TEST_DOCKER=0` turns it off. The socket is root on the Docker VM, which is fine for a local test agent only. Without it the agent reports "Docker not enabled" and the Images page stays empty.

### Verifying it worked

Query the DB directly rather than guessing from the agent's log output alone — a `pushed snapshot: N packages, M sockets` log line only means the HTTP call returned success, not that the data is well-formed (the `snapshots.reboot_packages` `NOT NULL` constraint has bitten this exact flow before). Something like:

```
docker exec security-whatnot-dev-postgres-1 psql -U swuser -d security_whatnot -c \
  "SELECT h.hostname, h.last_seen_at, s.os_id, s.os_version_id, s.public_ipv4, s.public_ipv6 FROM hosts h JOIN snapshots s ON s.host_id = h.id ORDER BY s.collected_at DESC LIMIT 5;"
```

A `NULL` `public_ipv6` is expected and correct on a machine with no IPv6 route — that's the agent's best-effort public-IP lookup degrading gracefully, not a bug. Don't chase it.

### Cleaning up test hosts

Test runs accumulate host rows with no automatic expiry. If asked to clean up, scope any `DELETE` to the specific host `id` (or the enrollment token/timeframe) you just created — `hostname` is not unique or stable (every enrollment mints a new UUID row even for an identical hostname), so a hostname-scoped delete can silently take out a *different*, possibly-still-wanted host row with the same name from an earlier session.
