# Version policy

Dependencies/base images were bumped to whatever was verified as
current-latest as of 2026-09-26 (Go 1.27.1 toolchain, Node 24-alpine,
Postgres 18.6-alpine, golang-migrate v4.20.1, TypeScript 7/tsgo, etc.) —
checked against live sources (registries, Docker Hub, nodejs.org), not
assumed from training data. **This will drift.** Re-audit periodically
rather than assuming pins in this repo stay current; don't trust a
memory or doc snapshot of "latest" over checking again.

One deliberate non-bump: `server/Dockerfile`'s runtime stage stays on
`alpine:3.20` — out of scope of the last audit pass, not yet re-checked.
