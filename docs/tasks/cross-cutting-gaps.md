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
- [ ] No CI pipeline (build/test/lint on push) configured.
- [x] Agent credential rotation: `POST /v1/agent/rotate`, agent-initiated
      on a push-response signal (dashboard request, 90-day age, or use of
      the pre-rotation secret), 1h grace for the old secret, atomic
      `credentials.json` (PROTOCOL.md §3).
- [x] Host management UI: rename / archive / merge / delete on Hosts,
      revoke / rotate on Agents.
- [ ] `agent/docker-compose.example.yml` references
      `ghcr.io/icondesk/upkeep-agent:latest` (so does the dashboard's
      `docker run` line), which doesn't
      exist yet — needs a build/publish pipeline before that snippet is
      actually usable end-to-end.
- [ ] Release supply chain (the realistic way the agent gets
      compromised, and with the Docker socket mounted a bad release is
      root on every opted-in host): sign agent images (cosign) with SBOM
      + build provenance; release only from tagged commits in CI;
      versioned tags (not `:latest`) in the compose example and the
      dashboard snippet so a bad release doesn't auto-propagate; 2FA and
      branch protection on the publishing account, narrowly scoped
      publish tokens.
- [x] Expired-enrollment-token cleanup: hourly River `credential_cleanup`
      job in the worker (also clears expired post-rotation secrets).
- [x] `server/Dockerfile` runtime base bumped `alpine:3.20` → `alpine:3.24`
      (latest minor on Docker Hub, 2026-09-29); the other base images were
      re-checked and are current (`docs/decisions/version-policy.md`).
