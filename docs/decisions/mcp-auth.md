# MCP auth: Better Auth OAuth plus API tokens, no installer CLI

Considered, 2026-10-04: how AI clients authenticate to `/api/mcp` ([MCP.md](../MCP.md#authentication)), and how
users set them up.

## OAuth first, through Better Auth's MCP plugin

**Decided: OAuth 2.1 sign-in, the way Clerk's MCP integration works, built with `@better-auth/mcp`.** In Claude
Code that's `claude mcp add --transport http upkeep <url>`, then `/mcp`, a browser sign-in and a consent page.
No secret to copy, paste or leak into shell history, and revoking access is one click.

- **Not Clerk itself.** [auth-self-hosted.md](auth-self-hosted.md) already rejected an auth vendor for a
  self-hosted security product. Clerk's flow is the standard MCP authorization spec, which Better Auth's plugin
  implements against our own Postgres, so we get the same user experience without the dependency.
- **Not hand-rolled.** OAuth servers are easy to get subtly wrong (PKCE, redirect URI matching, resource
  binding, refresh token rotation). The plugin owns all of that.
- **Client registration via CIMD**, the current MCP spec's preferred way (the client's id is a URL hosting its
  metadata). Dynamic Client Registration is deprecated in MCP and Better Auth leaves it off by default; enable
  it only if Claude Code still requires it when the endpoint is built.

### CIMD is enough for Claude Code: DCR stays off

Checked 2026-10-04 against Claude Code 2.1.289 while building PR 3 (`feat/mcp/3-endpoint`). **Decided: CIMD
only; Dynamic Client Registration is not enabled** (no `registration_endpoint` in our metadata).

- **Claude Code uses CIMD when the server offers it.** Its client sends
  `client_id=https://claude.ai/oauth/claude-code-client-metadata` when the authorization server metadata has
  `client_id_metadata_document_supported: true` (ours does, from `cimd()`), and falls back to DCR only when it
  doesn't, or when a custom callback isn't the document's loopback `/callback` (a debug line in the shipped
  client reads "withholding CIMD client_id — registering via DCR").
- **The document fits our checks.** It names the client "Claude Code", uses `token_endpoint_auth_method:
  none` and the loopback redirect URIs `http://localhost/callback` and `http://127.0.0.1/callback`; Better Auth
  treats CIMD clients as native apps and matches loopback redirects on any port (RFC 8252).
- **End to end:** an authorization code + PKCE flow with that `client_id` against a scratch instance created
  the client from the document (`oauth_clients.name` "Claude Code"), showed the consent page, issued an access
  token bound to `/api/mcp` plus a refresh token, and served `initialize`, `tools/list` and `tools/call`.
- **Cost of the choice:** the instance must be able to fetch `https://claude.ai/…` once an hour per client
  (metadata cache), so an air-gapped install can't sign in Claude Code until API tokens (PR 9) exist.

## Better Auth 1.7.7, pinned exactly

The MCP plugin is stable: `@better-auth/mcp` 1.7.7 (with `@better-auth/oauth-provider` and `@better-auth/cimd`
at the same version) requires `better-auth ^1.7.7`; we ran `^1.7.6`. **Decided: pin `better-auth` and every
`@better-auth/*` package to exactly 1.7.7** (no `^`), the bump in its own PR with a full regression pass of the
existing auth (bootstrap sign-up, closed sign-up, admin-created accounts, temporary passwords, disable, role
change).

Auth is security-sensitive, so the pin is deliberate: upgrades are explicit PRs, read against the changelog,
and every `@better-auth/*` package moves in lockstep with `better-auth`.

An earlier draft of this plan said the plugin needed a "1.8 beta": that came from a docs-site banner. npm had no
1.8 build on 2026-10-04 (`latest` 1.7.7; the `beta` tag is an old 1.7.0 prerelease).

**Applied** in PR 1 (`feat/mcp/1-pin-better-auth`): `better-auth` pinned to exactly `1.7.7`, no code changes and
no migration (Better Auth's 1.7.7 schema generator, the `auth` package, found our migrated schema up to date).

## API tokens second, for headless agents

OAuth needs a browser. `claude -p` in cron, CI and the Agent SDK don't have one, so **API tokens** (`upk_…`,
sent as a bearer header) follow later in the same stack. Users choose 30, 90 or 365 days, or never;
90 is the default. "Never" is allowed because headless agents break silently when a token expires; the
settings page shows last use so stale tokens are easy to spot and revoke.

## Roles come from the user, not the credential

Neither an OAuth grant nor an API token stores a role. Every call loads the user from `users` (role, disabled,
temporary password), the same check the dashboard does on every request (`lib/viewer.ts`). Demoting, disabling
or removing someone applies to their MCP access on the next call, with nothing to revoke by hand. Members can
connect; they get read access, which is all there is today.

## No installer CLI

Clerk ships `clerk mcp install`, which finds AI clients on the machine and writes their config. **Decided: no
equivalent.** The supported client is Claude Code, where setup is one `claude mcp add` command, so
**Settings → Integrations → Connect** shows that command with the instance URL filled in. A CLI would be another
artifact to build, sign, publish and version for a one-line saving. Revisit if more clients become supported.
