# MCP server

Spec, 2026-10-04. Status: **planned**. The build plan and the PR stack are in
[tasks/mcp-server.md](tasks/mcp-server.md); the reasoning behind the main choices is in
[decisions/mcp-server-in-web.md](decisions/mcp-server-in-web.md) and
[decisions/mcp-auth.md](decisions/mcp-auth.md). Where this doc and the code disagree, the code wins.

## Summary

upkeep.sh serves a remote [MCP](https://modelcontextprotocol.io) server at **`/api/mcp`** on the dashboard's
domain, so an AI client such as Claude Code can ask questions about the estate: which vulnerabilities to fix
first, what to upgrade on a host, where a vulnerable package sits inside an image, and whether a fix has landed.

- **Read-only.** The first release has only read tools. Nothing an AI client calls changes data in upkeep.sh.
- **Facts, not execution.** The MCP server never runs anything on a host. Claude applies fixes with its own
  tools (a shell, SSH, the user's repo) under the user's own permission prompts, then uses upkeep.sh to check
  the result. This keeps the agent's "collects facts only" property ([ARCHITECTURE.md](ARCHITECTURE.md)) true
  for the whole product.
- **Signed in as you.** Claude Code signs in through the browser with OAuth, the same way it connects to
  Clerk's or GitHub's MCP servers: `claude mcp add`, then `/mcp`, then sign in to upkeep.sh and approve. Headless
  agents (cron, CI, the Agent SDK) use an **API token** instead.
- **Claude Code is the supported client.** Other MCP clients that implement the spec may work, but the docs,
  the Connect tab and the tests cover Claude Code only (see [Clients](#clients)).
- **Every call is logged** for 90 days and visible under **Settings → Integrations → Activity**.

## Stories

1. *As an administrator or member*, under **Settings → Integrations → Connect** I copy one command,
   `claude mcp add --transport http upkeep https://upkeep.example.com/api/mcp`, with my instance's URL already
   filled in. I run `/mcp` in Claude Code, pick `upkeep`, and a browser opens on upkeep.sh.
2. *If I'm not signed in*, I sign in first. A consent page then names the client ("Claude Code"), says what it
   will be able to do ("read your workspace's hosts, images and vulnerabilities") and offers Allow / Deny.
3. *As a user*, I ask Claude "what are the top 15 vulnerabilities I should fix, and how?". Claude calls
   `list_top_vulnerabilities` and `get_host_remediation` and answers with packages, current and fixed versions,
   affected hosts and dashboard links.
4. *As a user*, I ask Claude to patch `web-01`. Claude gets the remediation data from upkeep.sh, runs the
   upgrade over SSH itself (I approve each command in Claude Code), then calls `get_finding_status` until the
   host's next snapshot shows the findings resolved.
5. *As a user*, I ask "why is my nginx image red?". Claude calls `get_image_vulnerabilities`, sees that most
   findings come from the image's OS packages (the base image), and proposes bumping `FROM` instead of patching
   packages. Claude picks the newer tag itself; upkeep.sh doesn't suggest target tags.
6. *As a user*, under **Connected apps** I see each client I've authorized (name, when, last used) and can
   revoke it. The next call from that client fails and Claude Code asks me to sign in again.
7. *As a user*, under **API tokens** I create a token for a headless agent: a name and an expiry (30, 90 or 365
   days, or never; 90 by default). The token is shown once. The list shows its prefix, creation date, last use
   and expiry, and I can revoke it.
8. *As an administrator*, I see every user's connected apps and tokens and can revoke any of them, and I see
   every user's calls under **Activity**. A member sees only their own.
9. *As an administrator*, when I disable an account, change a role or remove a member, it applies to that
   person's MCP access on the next call: roles are read from `users` on every call, never stored in a token.

## Clients

**Supported: Claude Code.** It connects from the user's machine, so the instance doesn't need to be on the
public internet: a dashboard reachable over a VPN or on the LAN works.

**Not promised: Claude Desktop and claude.ai connectors.** Their remote connectors are reached from
Anthropic's servers, so the instance would have to be publicly reachable, and they're a separate surface to
test. They may work because the server follows the MCP spec, but the Connect tab doesn't offer them and bug
reports about them aren't release blockers. Revisit if users ask.

There is **no installer CLI** (no `upkeep mcp install` like `clerk mcp install`): the Connect tab shows the
exact commands to paste. See [decisions/mcp-auth.md](decisions/mcp-auth.md#no-installer-cli).

## Authentication

Two ways to call `/api/mcp`, both ending in the same **MCP viewer**.

### OAuth (interactive clients)

Better Auth's `@better-auth/mcp` plugin makes the dashboard an OAuth 2.1 authorization server for MCP clients
(with `jwt()` for signing keys and `cimd()` for Client ID Metadata Documents). It serves the discovery
documents (RFC 8414 authorization server metadata, RFC 9728 protected resource metadata), PKCE authorization,
token issuance and refresh, and the `WWW-Authenticate` challenge a client gets when it calls without a token.

- **Login page:** the existing `/login`, which returns to the authorization request afterwards.
- **Consent page:** a new `/oauth/consent`: client name and the host of its metadata URL or redirect URI, the
  requested scopes in plain words, Allow / Deny. A user on a temporary password is sent to `/change-password`
  first.
- **Scopes:** `mcp:read` (every tool today). `mcp:write` is reserved for the later write tools and will
  additionally require the admin role at call time.
- **Client registration:** CIMD. Dynamic Client Registration stays off unless Claude Code still needs it when
  PR 3 is built (checked then; see the task list).
- **Tokens:** short-lived access tokens bound to the `/api/mcp` resource, plus refresh tokens
  (`offline_access`) so Claude Code stays connected without signing in every hour.

### API tokens (headless agents)

For `claude -p` in cron or CI, the Agent SDK, or any client that can't do a browser sign-in. Sent as
`Authorization: Bearer upk_…`, so `claude mcp add` takes it with `--header`.

- Created under **Settings → Integrations → API tokens** with a name and an expiry: 30, 90 or 365 days, or
  never. 90 days is the default. The list warns 7 days before a token expires.
- Shown once. Only a hash is stored; the list shows the `upk_` prefix plus the first few characters.
- Carries `mcp:read` only, like OAuth grants. When write tools exist, a token's scopes are chosen at creation,
  and only an administrator can create a write token.
- Built on Better Auth's API key plugin (`@better-auth/api-key`) if it fits at the pinned version (prefix,
  hashing, optional expiry, last-used), otherwise our own `api_tokens` table. Decided in PR 9.

### The MCP viewer

The dashboard resolves a `Viewer` from the session cookie (`lib/viewer.ts`). MCP requests have no cookie, so
`/api/mcp` resolves the same `Viewer` from the bearer credential instead:

1. Verify the credential (OAuth access token via `requireMcpAuth`, or API token), which gives a user id.
2. Load the user exactly as `getViewer` does: role, `disabled_at`, `must_change_password`, from `users` on
   every call. Disabled or unknown users are refused (401). A user on a temporary password gets a tool error
   telling them to sign in to the dashboard and choose a password.
3. The workspace is the install's workspace (`getWorkspaceId()`), as for every other request.

Refactor `getViewer` so the cookie path and the bearer path share the user lookup (`viewerForUser(userId)`),
so the two can't drift.

## Tools

All read-only, all scoped to the install's workspace, all available to members and administrators. Each tool
returns **structured content** (JSON matching a declared output schema) plus a short text rendering for clients
that ignore structured content. Every item carries a `dashboard_url` so Claude can link the user to the page.

Hosts are addressed by id or hostname; an ambiguous hostname returns an error listing the candidates. Images
are addressed by id (or the 12-character short id), digest or reference (`nginx:1.27`, `repo@sha256:…`, or a bare
repository for any of its tags), plus `platform` when one id has several; an unknown or ambiguous image is an
error listing the candidates. Lists take `limit` (default 15, maximum 100) and
return a `truncated` flag rather than paging, so a client can't walk the whole database by accident.

| Tool | Arguments | Returns | Built on |
| --- | --- | --- | --- |
| `get_workspace_summary` | none | Hosts and images by state, open findings by severity, KEV count, hosts needing a reboot, stale hosts, latest report | `getOverviewStats`, `getEstateHealth`, `getFleetVulnCounts`, `getLatestReport` |
| `list_attention_items` | `limit` | The overview's "Needs attention" list | `getAttentionItems` |
| `list_top_vulnerabilities` | `limit`, `kind` (`host`, `image`, `all`), `min_severity`, `kev_only`, `fixable_only`, `host` | Vulnerabilities in the dashboard's rank order (`severity_rank`: KEV, EPSS, CVSS), each with affected host and image counts and whether a fix exists | `getFleetVulnList` |
| `get_vulnerability` | `id` (CVE or advisory id) | Summary, CVSS, EPSS, KEV, fixed version per distro release, affected hosts and images | `getFleetVulnDetail` |
| `list_hosts` | `query`, `state`, `limit` | Hosts with OS, health state, open findings, agents, last seen, worst state first | `getEstateHealth`, `getHosts` |
| `get_host` | `host` | OS and kernel (running and installed), reboot pending, uptime, automatic updates, last snapshot time, collector status, finding counts | `getHost`, `getHostSystem`, `getHostVulnSummary`, `getHostImageVulnSummary`, `getHostKernels` |
| `get_host_remediation` | `host`, `min_severity`, `kev_only`, `limit` | One entry per vulnerable package: installed version, the highest fixed version across its findings (dpkg order), CVEs closed with severity and KEV, whether it's a kernel package (reboot needed) and whether the fix needs Ubuntu Pro. Packages without a fix are listed separately; `limit` applies to each list | `getHostRemediation` (`queries-remediation.ts`): the host tab's open package findings grouped by source package, kernels from `getHostKernels` |
| `find_package` | `name`, `version` (prefix), `kind` (`host`, `image`, `all`) | Hosts and images that have the package, by binary or source name, with versions and whether each is vulnerable; image matches carry the package's origin and paths. `limit` applies to each kind | `findPackageOnHosts` over `host_software`, `findPackageInImages` over `image_software` (`queries-package-search.ts`) |
| `list_images` | `query`, `limit` | Images on the workspace's hosts, most urgent first: scan state, base OS release, vulnerability counts (severity, KEV, fixable), open findings, and the hosts and running containers that have them | `getImageList` (`queries-image-list.ts`) on `image_scores` (`queries-image-scores.ts`) |
| `get_image_vulnerabilities` | `image`, `platform`, `min_severity`, `kev_only`, `limit` | Vulnerabilities with package, versions and **origin**: the image's OS packages (deb, apk, rpm: nearly always the base image, fixed by a newer `FROM`) or application packages at their paths; counts per origin and the base OS release. upkeep.sh doesn't record which layer installed a package, so origin goes by ecosystem, not layer | `getImageVulns`, `getImageVulnEcosystems`, `getImageOverview` |
| `get_finding_status` | `host` or `image` (and `platform`), plus `package` or `vulnerability` | Host: open or resolved (with when), and the time of the latest snapshot, so Claude can tell "not fixed" from "not re-scanned yet": the agent's push interval and the package's versions installed now come along. Image: whether the image still has it and how current its scan is; a rebuilt image is a new id, so Claude asks by tag | `getFindingStatus`, `getImageFindingStatus` (`queries-finding-status.ts`) |
| `list_resolved` | `since` (default 7 days ago), `host`, `limit` | Host package and image findings resolved since a time, newest first | `getResolvedFindings` over `findings` |

**Data only, no commands.** `get_host_remediation` returns packages and versions, never `apt-get …` or
`apk …` lines. Claude works out the command for the host it's on, which keeps distro quirks (held packages,
pinned repos, `needrestart`) out of upkeep.sh.

**No prompts or resources** in the first release, only tools. MCP prompts would appear as slash commands
(`/mcp__upkeep__triage`) and resources as `@`-mentionable records; both can be added later without changing
the tools.

## Activity log

Every call to `/api/mcp` that reaches a tool writes one row to `mcp_calls`:

| Column | |
| --- | --- |
| `id`, `workspace_id`, `created_at` | |
| `user_id` | Who the credential belongs to |
| `credential_kind` | `oauth` or `api_token` |
| `oauth_client_id` / `api_token_id` | Which grant or token (one of the two is set) |
| `client_name` | The client's name at call time (it can change or be deleted later) |
| `tool` | Tool name |
| `arguments` | The call's arguments (jsonb). Arguments are filters and identifiers, not secrets |
| `result_items` | Number of items returned |
| `duration_ms` | |
| `error` | Error message, or NULL |

- **Retention:** 90 days. The worker's hourly `alert_prune` job deletes older rows, next to the retention it
  already applies to events, notifications and reports.
- **Who sees what:** administrators see every call, members see their own, under **Settings → Integrations →
  Activity** (TanStack table, filter by user, client and tool).
- **Read tools log best effort:** if the insert fails, the call still returns and the server logs the failure.
  Write tools (later) will fail closed: no log row, no write.
- Failed authentication isn't logged here (there's no user to attribute it to); it goes to the server log.

## Settings → Integrations

A new settings section (`settingsSections`), visible to members and administrators, with four tabs:

- **Connect:** the `claude mcp add` command with this instance's URL (from `BETTER_AUTH_URL`), the `/mcp` sign-in
  steps, and the headless variant with `--header "Authorization: Bearer upk_…"` linking to API tokens.
- **Connected apps:** OAuth grants: client, user (admins), scopes, authorized, last used, Revoke. Revoking
  deletes the consent and its access and refresh tokens.
- **API tokens:** create (name, expiry), the one-time reveal, list (name, prefix, user for admins, created, last
  used, expires), Revoke.
- **Activity:** the call log above.

## Security notes

- **No execution path.** No tool runs commands, and none will reach a host through the server's SSH keys for
  remote hosts. A prompt-injected client can read what its user can read, nothing more.
- **Advisory text is untrusted input.** Advisory summaries and package metadata come from upstream feeds and
  package authors. Tools return them as clearly labeled data fields, truncated to a few hundred characters,
  never as instructions or bare prose mixed into the tool's own text.
- **Rate limit:** per credential, in memory (the web app runs as one process), generous enough for an agent
  loop (on the order of 120 calls a minute). A limit hit returns a tool error, not a 500.
- **Origin checks:** `/api/mcp` validates the `Origin` header when present, as the MCP transport spec requires,
  to block DNS rebinding against a dashboard on a private network.
- **CSRF and cookies:** `/api/mcp` ignores session cookies entirely. Only bearer credentials authenticate there.

## Not in this release

Each is a later stack, not a forgotten item:

- **Write tools** (`mcp:write`, admin only): suppress or accept a finding, request an image rescan, ask an agent
  for a fresh snapshot. They need features that don't exist yet (suppression) and a fail-closed log.
- **A Claude Code plugin** with `patch-host` and `patch-image` skills that encode a safe procedure (simulate
  first, one host at a time, check for a pending reboot, verify through upkeep.sh).
- **Prompts and resources.**
- **Layer attribution for image findings**: which layer installed each package, base image or added on top.
  Registry SBOM attestations carry a layer id per package, but the parser drops it and the image scanner
  flattens the layers; `get_image_vulnerabilities` goes by ecosystem until then.
- **Claude Desktop and claude.ai connectors** as supported clients.
