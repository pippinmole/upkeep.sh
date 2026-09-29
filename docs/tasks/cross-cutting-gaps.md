# Cross-cutting gaps worth closing before real users
- [ ] `container_images` metadata (created, layers, labels) is
      first-writer-wins across users: the first agent to report an image
      key writes it and nobody can change it afterwards. Package lists
      are already trust-scoped (server lists fleet-wide, agent lists per
      user, [Container image vulnerabilities](../decisions/container-image-vulnerabilities.md)), but this row
      is not: one user's agent could plant wrong labels for an image id
      another user also has. Scope it per user or only accept it from
      server-side inspection before the dashboard shows it as fact.
- [ ] Tests: dpkg status parsing, OS detection and the inventory range
      diff / set hash / old-agent rules now have tests (server store tests
      need `SW_TEST_DATABASE_URL`, otherwise skipped). Still missing: dpkg
      version comparison (once written), `/proc/net/tcp` parsing, and the
      ingest handler's auth path.
- [x] CI pipeline: `.github/workflows/ci.yml` builds, vets, lints and
      tests agent, server (store/jobs/ingest integration tests against a
      migrated Postgres service) and web on every push and PR, and builds
      all three Docker images (no push).
- [x] Agent credential rotation: `POST /v1/agent/rotate`, agent-initiated
      on a push-response signal (dashboard request, 90-day age, or use of
      the pre-rotation secret), 1h grace for the old secret, atomic
      `credentials.json` (PROTOCOL.md §3).
- [x] Host management UI: rename / archive / merge / delete on Hosts,
      revoke / rotate on Agents.
- [x] Agent image namespace and pin: the compose example and the
      dashboard's `docker run` line used `ghcr.io/icondesk/upkeep-agent:latest`,
      which never existed. Both now pin `ghcr.io/pippinmole/upkeep-agent:0.1.0`
      from one place (`web/src/lib/agent-image.ts`, `SW_AGENT_IMAGE`
      overrides it at runtime); `scripts/check-version-pins.sh` keeps the
      two in step.
- [x] Release supply chain, pipeline side (the realistic way the agent
      gets compromised, and with the Docker socket mounted a bad release
      is root on every opted-in host): `.github/workflows/release.yml`
      publishes agent, server and web to GHCR only from a `vX.Y.Z` tag
      reachable from `main` whose version matches the pins; multi-arch;
      BuildKit SBOM + max provenance; cosign keyless signature on the
      digest; GitHub build provenance attestation (only while the repo is
      public); `GITHUB_TOKEN` only, no stored publish tokens; write
      permissions only in the publish job, behind a `release`
      environment; exact versions (not `:latest`) in the compose example
      and dashboard snippet. [RELEASING.md](../RELEASING.md).
- [ ] Release supply chain, **waiting on owner**
      ([RELEASING.md owner checklist](../RELEASING.md#owner-checklist-account-settings-by-hand)):
      fix Actions billing / spending limit; 2FA on the publishing
      account; ruleset on `main` (PR + required checks, no force-push or
      deletion) and on `v*` tags; read-only default workflow permissions;
      required reviewer on the `release` environment; cut the first real
      release `v0.1.0`, then make the three GHCR packages public.
- [x] Expired-enrollment-token cleanup: hourly River `credential_cleanup`
      job in the worker (also clears expired post-rotation secrets).
- [x] `server/Dockerfile` runtime base bumped `alpine:3.20` → `alpine:3.24`
      (latest minor on Docker Hub, 2026-09-29); the other base images were
      re-checked and are current (`docs/decisions/version-policy.md`).
