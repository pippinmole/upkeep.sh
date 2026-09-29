# Version policy

Dependencies/base images were bumped to whatever was verified as
current-latest as of 2026-09-26 (Go 1.27.1 toolchain, Node 24-alpine,
Postgres 18.6-alpine, golang-migrate v4.20.1, TypeScript 7/tsgo, etc.) —
checked against live sources (registries, Docker Hub, nodejs.org), not
assumed from training data. **This will drift.** Re-audit periodically
rather than assuming pins in this repo stay current; don't trust a
memory or doc snapshot of "latest" over checking again.

Last re-audit: 2026-09-29, against Docker Hub tags
(`registry.hub.docker.com/v2/repositories/<repo>/tags`), go.dev/dl,
nodejs.org's `dist/index.json` + the nodejs/Release schedule, and the
oven-sh/bun GitHub releases:

- `server/Dockerfile` runtime: `alpine:3.20` → `alpine:3.24` (3.24.2 is
  the newest tag; no 3.25 exists yet).
- `golang:1.27.1-alpine` (agent, server build): current (Go 1.27.1).
- `oven/bun:1.4.2-alpine` (web build): current (bun v1.4.2).
- `node:24-alpine` (web runtime): kept. Node 24 is still Active LTS
  (v24.21.0); Node 26 isn't LTS until 2026-10-28, so revisit after that.
