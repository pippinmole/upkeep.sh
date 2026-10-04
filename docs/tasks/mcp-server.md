# MCP server

Spec: [MCP.md](../MCP.md). Decisions: [mcp-server-in-web.md](../decisions/mcp-server-in-web.md),
[mcp-auth.md](../decisions/mcp-auth.md). A read-only MCP server at `/api/mcp` in the Next.js app, OAuth sign-in
through Better Auth plus API tokens, a 90-day call log and **Settings → Integrations**.

## How this is built: one gh stack

The work ships as **one stack of ten PRs** managed with the [`gh stack`](https://github.com/github/gh-stack)
extension. Each PR is based on the one below it, not on `main`, so each diff is only that step's change.

- **Branches:** `feat/mcp/<n>-<slug>`, numbered bottom to top. The number keeps the order obvious in
  `git branch` and on GitHub.
- **Each PR stands on its own:** it builds, passes `hk check --all`, the web typecheck, lint, tests and build,
  and `go vet` / `go test` where `server/` changes. A reviewer can check out any branch and try it.
- **Commits:** Conventional Commits with the area as scope (CLAUDE.md). PR titles below are the squash-free
  merge titles; each PR may hold several commits.
- **Foundation first:** auth and schema go in before any UI, so each UI PR can be tested end to end against a
  real endpoint when it lands.

```text
main
 └─ feat/mcp/0-docs                  docs: plan the MCP server
     └─ feat/mcp/1-better-auth-1-8   chore(web): pin Better Auth 1.8 beta
         └─ feat/mcp/2-schema        feat(server): add MCP OAuth and call log tables
             └─ feat/mcp/3-endpoint  feat(web): serve /api/mcp with OAuth sign-in
                 └─ feat/mcp/4-settings        feat(web): add Settings → Integrations
                     └─ feat/mcp/5-tools-vulns   feat(web): add MCP vulnerability tools
                         └─ feat/mcp/6-tools-hosts   feat(web): add MCP host tools
                             └─ feat/mcp/7-tools-images  feat(web): add MCP image tools
                                 └─ feat/mcp/8-activity    feat(web): show MCP activity and prune it
                                     └─ feat/mcp/9-api-tokens  feat(web): add API tokens for headless MCP clients
```

### Working the stack

```sh
# Each branch is created from the one below it as work starts.
git switch -c feat/mcp/1-better-auth-1-8 feat/mcp/0-docs

# Once the branches exist, adopt them bottom to top, then push and open the PRs.
gh stack init feat/mcp/0-docs feat/mcp/1-better-auth-1-8 feat/mcp/2-schema …
gh stack submit --auto --open
# submit generates titles: set the titles above (and bodies) with `gh pr edit <n>`.
```

- **Review changes on a lower PR:** commit on that branch, then rebase everything above it in one go with
  `git rebase --update-refs` from the top branch (or gh stack's own rebase), and push the stack again.
- **Adding branches later:** create the new top branch from the current top, then re-run `gh stack init` with
  the full list, bottom to top.
- **Merging:** `gh stack merge <stack#> --yes --merge` merges the whole stack atomically with merge commits.
  The stack can also be merged from the bottom in parts, e.g. 0–3 first, if the top half is still in review.
  After merging, check `git branch --show-current`: the checkout can be left on a stack branch.

## The stack, PR by PR

### PR 0: `feat/mcp/0-docs` (docs: plan the MCP server)

- [ ] [MCP.md](../MCP.md) spec, the two decisions, this task file, and the index entries in
      [decisions/README.md](../decisions/README.md), [tasks/README.md](README.md) and
      [ARCHITECTURE.md](../ARCHITECTURE.md).

### PR 1: `feat/mcp/1-better-auth-1-8` (chore(web): pin Better Auth 1.8 beta)

No MCP code. Only the upgrade, so a regression bisects to this PR.

- [ ] Bump `better-auth` (and `@better-auth/*` if any) to the latest 1.8 beta, **exact pins** (no `^`) in
      `web/package.json`; `bun install`, commit `bun.lock`.
- [ ] Apply any 1.7 → 1.8 breaking changes from the changelog to `lib/auth.ts` and `lib/auth-client.ts`.
- [ ] Check whether 1.8 wants schema changes to `users`, `sessions`, `accounts`, `verifications`
      (`@better-auth/cli generate` against a scratch database, compared with migration 0018). If so, add a
      migration in this PR, mapped to our snake_case names like 0018.
- [ ] Regression pass, by hand against the dev stack (start-dev skill): fresh install bootstrap sign-up
      becomes admin; second sign-up refused (form and direct API call); admin creates a member with a temporary
      password; forced `/change-password`; sign-out; disable signs the user out and blocks sign-in; role change
      applies on the next request.
- [ ] Web typecheck, lint, test, build. Note the pinned version in
      [decisions/mcp-auth.md](../decisions/mcp-auth.md).

### PR 2: `feat/mcp/2-schema` (feat(server): add MCP OAuth and call log tables)

Migrations live in `server/migrations/` (the contract between `server/` and `web/`), hence the `server` scope.

- [ ] Migration `00NN_mcp` (next free number; 0026 at the time of writing), up and down:
  - [ ] The `@better-auth/mcp` / OAuth provider models (`oauthClient`, `oauthAccessToken`, `oauthRefreshToken`,
        `oauthConsent`, `oauthClientAssertion`) and the `jwt()` plugin's `jwks`, generated with
        `@better-auth/cli generate` and translated to snake_case tables (`oauth_clients`, …) with `uuid` ids and
        `users(id) ON DELETE CASCADE`, following 0018. Record the model → table/field mapping in the migration
        header; PR 3 repeats it in `lib/auth.ts`.
  - [ ] `mcp_calls` as specified in [MCP.md](../MCP.md#activity-log), with `workspace_id`, foreign keys to the
        user and OAuth client (`ON DELETE SET NULL` for the client, so the log outlives a revoked grant), and an
        index on `(workspace_id, created_at DESC)` plus `(user_id, created_at DESC)`.
  - API token tables are **not** here: PR 9 decides between the Better Auth plugin and our own table.
- [ ] [ARCHITECTURE.md](../ARCHITECTURE.md) "Who owns what": the OAuth tables and `jwks` written by Next.js
      (Better Auth), `mcp_calls` written by Next.js and pruned by Go (`alert_prune`).
- [ ] `go test ./...` in `server/` with `-tags integration` (migrations up, down and up again on a throwaway
      database).

### PR 3: `feat/mcp/3-endpoint` (feat(web): serve /api/mcp with OAuth sign-in)

The whole auth path end to end, with one tool to prove it.

- [ ] `lib/auth.ts`: add `jwt()`, `cimd()` and `mcp({ loginPage: "/login", consentPage: "/oauth/consent",
      resource: <BETTER_AUTH_URL>/api/mcp })` with the table mapping from PR 2. `nextCookies()` stays last.
- [ ] Check what Claude Code supports at build time: CIMD, or does it still need Dynamic Client Registration?
      Enable DCR only if it's required, and record which in [decisions/mcp-auth.md](../decisions/mcp-auth.md).
- [ ] Discovery: serve the RFC 9728 protected resource metadata
      (`/.well-known/oauth-protected-resource/api/mcp`) and RFC 8414 authorization server metadata at the paths
      the plugin derives from the issuer, as Next.js routes under `app/.well-known/`.
- [ ] `/login` honors the plugin's return-to so sign-in continues the authorization request.
- [ ] `/oauth/consent` page: client name, metadata URL host, scopes in plain words, Allow / Deny. Temporary
      password → `/change-password` first, then back.
- [ ] `lib/viewer.ts`: extract `viewerForUser(userId)` from `getViewer`; add `getMcpViewer(request)` for
      bearer credentials (OAuth only for now; the API token branch comes in PR 9). Tests for disabled, unknown
      and temporary-password users.
- [ ] `app/api/mcp/route.ts`: MCP TypeScript SDK v2, stateless Streamable HTTP, wrapped in `requireMcpAuth`.
      Ignores cookies; validates `Origin`; per-credential in-memory rate limit.
- [ ] `lib/mcp/`: server setup, a small `defineTool` helper (zod input and output schemas, structured content
      plus a text rendering, `dashboard_url` building, call logging, error mapping), and `get_workspace_summary`.
- [ ] Call logging into `mcp_calls`, best effort (see [MCP.md](../MCP.md#activity-log)).
- [ ] Tests: `defineTool` (schema validation, error mapping, logging); the viewer resolution.
- [ ] By hand: `claude mcp add --transport http upkeep http://localhost:3000/api/mcp`, `/mcp`, sign in,
      consent, ask for a summary; then revoke the consent in the database and see Claude Code ask again. Note
      the steps in `web/README.md`.

### PR 4: `feat/mcp/4-settings` (feat(web): add Settings → Integrations)

- [ ] `settingsSections` entry "Integrations" (`/dashboard/settings/integrations`, a plug icon, keywords: mcp,
      claude, ai, oauth, tokens, api), visible to members and admins.
- [ ] Tabs layout (Connect, Connected apps; API tokens and Activity arrive in PRs 9 and 8).
- [ ] **Connect:** the `claude mcp add` command with the instance URL, a copy button, the `/mcp` steps.
- [ ] **Connected apps:** a TanStack table of OAuth consents (client, user for admins, scopes, authorized,
      last used), Revoke via a server action that deletes the consent and its tokens. Members revoke their own;
      admins any. Server-side checks, not only hidden buttons.
- [ ] Tests for the revoke action's permission rules. react-doctor on the new components.

### PR 5: `feat/mcp/5-tools-vulns` (feat(web): add MCP vulnerability tools)

- [ ] `list_attention_items`, `list_top_vulnerabilities`, `get_vulnerability` per the
      [tool table](../MCP.md#tools), on the existing queries. Shared argument schemas (severity, limit) in
      `lib/mcp/args.ts`.
- [ ] Advisory text fields truncated and labeled as data ([MCP.md](../MCP.md#security-notes)).
- [ ] Tests: argument validation, ordering matches the dashboard's list for the same filters, the `truncated`
      flag.

### PR 6: `feat/mcp/6-tools-hosts` (feat(web): add MCP host tools)

- [ ] Host lookup by id or hostname with the ambiguous-hostname error (`lib/mcp/resolve.ts`).
- [ ] `list_hosts`, `get_host`, `get_host_remediation` (new grouped-by-package query: highest fixed version
      across the package's findings, kernel flag, unfixable packages listed apart), `find_package` (hosts
      only here; images in PR 7), `get_finding_status`, `list_resolved`.
- [ ] Tests for the remediation grouping (several findings on one package, mixed fixed and unfixed, kernel).
- [ ] By hand: the "patch web-01" story from [MCP.md](../MCP.md#stories) against a dev agent.

### PR 7: `feat/mcp/7-tools-images` (feat(web): add MCP image tools)

- [ ] Image lookup by id, reference or digest.
- [ ] `list_images`, `get_image_vulnerabilities` with layer attribution (`imageOriginSql`); `find_package` and
      `get_finding_status` extended to images.
- [ ] Tests for lookup and attribution output.

### PR 8: `feat/mcp/8-activity` (feat(web): show MCP activity and prune it)

- [ ] **Activity** tab: TanStack table over `mcp_calls` (time, user, client, tool, arguments, items, duration,
      error), filters by user, client and tool. Admins see all, members their own; enforced in the query.
- [ ] Worker: `alert_prune` also deletes `mcp_calls` older than 90 days; integration test.
- [ ] [ARCHITECTURE.md](../ARCHITECTURE.md): mention the retention next to the other `alert_prune` targets.

### PR 9: `feat/mcp/9-api-tokens` (feat(web): add API tokens for headless MCP clients)

- [ ] Decide: `@better-auth/api-key` (pinned like PR 1) if it gives a custom prefix, hashed storage, optional
      expiry and last-used tracking; otherwise our own `api_tokens` table. Record it in
      [decisions/mcp-auth.md](../decisions/mcp-auth.md).
- [ ] Migration for the token table (next free number), with ownership in ARCHITECTURE.md.
- [ ] `getMcpViewer`: `upk_` bearer credentials go to the token check, everything else to OAuth. Logged with
      `credential_kind = api_token`.
- [ ] **API tokens** tab: create (name; expiry 30, 90, 365 days or never; default 90), one-time reveal with
      copy, list (name, prefix, user for admins, created, last used, expires, expiring-soon badge within 7
      days), Revoke. Same permission rules as Connected apps.
- [ ] **Connect** tab: the headless variant with `--header "Authorization: Bearer upk_…"`.
- [ ] Tests: token verification (expired, revoked, never-expiring, disabled user), permission rules.
- [ ] By hand: `claude -p` with a token, then revoke it and see the 401.

## Later stacks (not part of this one)

- [ ] Write tools (`mcp:write`, admin only, fail-closed logging): suppress a finding (needs a suppression
      feature first), request an image rescan, request a fresh agent snapshot.
- [ ] Claude Code plugin with `patch-host` / `patch-image` skills.
- [ ] MCP prompts and resources.
- [ ] Claude Desktop and claude.ai connectors as supported clients.
- [ ] Move Better Auth from the 1.8 beta to 1.8 stable.
