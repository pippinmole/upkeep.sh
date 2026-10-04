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

## Better Auth 1.8 beta, pinned

The MCP plugin needs Better Auth 1.8, which is in beta (we run 1.7.6). **Decided: adopt it now, pinned to an
exact version** (no `^`) for `better-auth` and every `@better-auth/*` package, in its own PR with a full
regression pass of the existing auth (bootstrap sign-up, closed sign-up, admin-created accounts, temporary
passwords, disable, role change).

Auth is security-sensitive, so the pin is deliberate: upgrades are explicit PRs, read against the changelog.
**Follow-up:** move to 1.8 stable when it ships, and drop this beta note.

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
