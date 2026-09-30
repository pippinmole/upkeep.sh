# Decisions

A running log of the "why" behind non-obvious choices, so a fresh session
(or future you) doesn't relitigate them without new information. Ordered
roughly by when they were made.

- [Ingest API in Go, not Next.js API routes](ingest-api-in-go.md) — the agent protocol and background workers live in a persistent Go process, not Next.js route handlers.
- [Direct Postgres reads from Next.js](direct-postgres-reads.md) — the dashboard reads Postgres directly from server-side Next.js; writes are split by table; caching via revalidation if ever needed.
- [Auth: self-hosted Better Auth, not a managed vendor (Clerk/Auth0)](auth-self-hosted.md) — self-hosted Better Auth (username + password, database sessions), so the product doesn't depend on an auth vendor.
- [Single-user tenancy for MVP (no orgs/teams)](single-user-tenancy.md) — hosts belong directly to a user; an organization layer can be migrated in later. **Superseded** by [MEMBERS.md](../MEMBERS.md): one shared workspace per install with roles.
- [Billing deferred](billing-deferred.md) — free during beta, no Stripe or plan-gating fields until billing is built.
- [Email notifier: SMTP settings per channel, not platform config](email-notifier-smtp.md) — each email channel carries its own SMTP server; STARTTLS by default, no platform SMTP config.
- [Port exposure: host-side analysis, not an external scanner (MVP)](port-exposure.md) — classify exposure from host facts (listeners, ufw, Docker ports); external scanner deferred to Phase 2+.
- [Docker collection: Engine API from the agent, opt-in socket mount](docker-collection.md) — Docker Engine API via the official Go client over an opt-in socket mount; fixed read-only call list; local agents only.
- [Container image vulnerabilities: our own SBOM + matcher, not Docker Scout](container-image-vulnerabilities.md) — image package inventory (registry SBOM, Syft) matched by our own pipeline, not Docker Scout.
- [Scheduled reports: a separate feature, about state rather than events](scheduled-reports.md) — weekly/monthly estate reports about state, separate from alert rules, stored as snapshots and sent to existing channels.
- [Report email HTML: React Email, rendered by Next.js](report-email-html.md) — report emails are React Email HTML rendered by an internal Next.js endpoint and sent by the Go worker.
- [Next.js deploys as a Docker standalone image, not on Vercel](nextjs-docker-standalone.md) — the web app ships as a standalone Docker image for self-hosting, not on Vercel.
- [Package manager: Bun (migrated from npm)](package-manager-bun.md) — Bun for install/build in `web/`; the runtime image stays plain Node.
- [Linting/formatting: oxlint + oxfmt (migrated from ESLint)](linting-oxlint-oxfmt.md) — oxlint + oxfmt replaced ESLint.
- [Version policy](version-policy.md) — pins were verified current on 2026-09-26 and will drift; re-check live sources rather than trusting docs.
- [Postgres 18's data directory mount](postgres-18-data-mount.md) — Postgres 18 images need the volume at `/var/lib/postgresql`, not `.../data`.
