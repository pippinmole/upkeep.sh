# Members and roles

Spec, 2026-09-30. Status: **built** (migration `0023_members`, Settings >
Members). Where this doc and the code disagree, the code wins.

## Summary

An install has **one shared workspace**. Everyone who can sign in sees the
same hosts, agents, images, vulnerabilities, channels, alert rules and
reports. A **role** on each user decides whether they can change anything.

- **Administrator**: full access, including managing members.
- **Member**: read-only view of the whole product.

The first account created on a fresh install becomes the administrator.
After that, public sign-up is closed and administrators create accounts.

## Stories

1. *As the person installing upkeep.sh*, I open `/signup` on a fresh
   install, create the first account and land on the dashboard as its
   administrator.
2. *As anyone else*, `/signup` tells me sign-up is closed and to ask an
   administrator; `/login` no longer offers a sign-up link. The server
   refuses a sign-up request even if I call Better Auth directly.
3. *As an administrator*, under **Settings > Members** I add a person with
   a username, an email, an optional name, a role and a temporary password
   (typed or generated). I pass the username and password on myself; there
   is no invite email yet.
4. *As a new member*, I sign in with the temporary password and must pick
   my own password before I can see anything (`/change-password`).
5. *As a member*, I see everything an administrator sees, but no add,
   edit, delete, test or send buttons. If I call a server action directly,
   it's refused.
6. *As an administrator*, I can promote a member to administrator, demote
   an administrator, reset someone's password (a new temporary one; they
   are signed out everywhere), disable or re-enable an account (disabled
   accounts are signed out and can't sign in) and remove an account.
7. *As an administrator*, I can't lock myself out: I can't change my own
   role, disable, remove or reset myself from the Members page, and the
   install always keeps at least one enabled administrator.
8. *As any user*, I can change my own password from the user menu.

## Permission matrix

| Area | Action | Administrator | Member |
| --- | --- | :-: | :-: |
| All dashboard pages (overview, hosts, images, packages, vulnerabilities, swarm, agents, alerts, delivery log, reports, settings) | View | yes | yes |
| Hosts | Add (enrollment token, remote SSH host), rename, archive, merge, dismiss duplicate, delete, confirm host key, remove remote target | yes | no |
| Agents | Install (enrollment token), revoke, request rotation, detach host | yes | no |
| Notification channels | Create, edit, rotate secret, enable/disable, delete, **send test** | yes | no |
| Alert rules | Create, edit, enable/disable, delete | yes | no |
| Report schedules | Create, edit, enable/disable, delete, **send now** | yes | no |
| Members | View the list | yes | yes |
| Members | Add, change role, reset password, disable/enable, remove | yes (not on themselves) | no |
| Own account | Change own password | yes | yes |
| Agent ingest (`/v1/enroll`, `/v1/snapshots`, `/v1/agent/*`) | Authenticated by agent credentials, not users; unaffected | n/a | n/a |

"Send test" and "Send now" are writes: they create notifications and
deliveries and contact external endpoints, so they are admin-only.

## Enforcement

- **Server side** (the actual control): every mutating server action calls
  `requireAdmin()` (`web/src/lib/viewer.ts`) before touching the database:
  `app/dashboard/actions.ts`, `manage-actions.ts`,
  `notification-actions.ts` and `settings/members/actions.ts`. The role is
  read from the `users` row on every request, not from the session, so a
  role change or a disable applies immediately. There are no mutating
  route handlers under `app/dashboard` today; any new one must call
  `requireAdmin()` too. The Go API has no user-facing endpoints (only the
  agent protocol), so it needs no role checks.
- **Sign-up lockout**: `web/src/lib/auth.ts` refuses user creation once any
  user exists, in two places: a Better Auth `hooks.before` on
  `/sign-up/email` and a `databaseHooks.user.create.before` (which covers
  any other path that creates a user). The Members "Add member" action
  passes both by running Better Auth's sign-up inside
  `asAdminAccountCreation()` (an `AsyncLocalStorage` flag that only server
  code can set). `emailAndPassword.autoSignIn` is off so creating an
  account never signs the admin in as it; the bootstrap sign-up signs in
  explicitly.
- **First admin**: `databaseHooks.user.create.after` makes the oldest user
  the admin. If two sign-ups race on a fresh install, both can be created
  but only the first becomes admin; the other is a member.
- **Disabled accounts**: `users.disabled_at`; a
  `databaseHooks.session.create.before` refuses sign-in, sessions are
  deleted when the account is disabled, and `getViewer()` treats a
  disabled user as signed out.
- **Temporary passwords**: `users.must_change_password`, set on admin
  create and reset. The dashboard layout (`requireViewer()`) redirects to
  `/change-password`, and `requireActionViewer()` / `requireAdmin()`
  refuse actions until the user has chosen a password.
- **Guard rails** (`settings/members/actions.ts`): in one transaction that
  locks every admin row plus the actor and target, the actor must still be
  an enabled admin, the target must not be the actor, and after the change
  at least one enabled admin must remain. Locking serialises two admins
  acting on each other at the same time.
- **UX layer**: the dashboard layout provides the role to client
  components (`components/viewer-context.tsx`); write controls are wrapped
  in `adminOnly()` and don't render for members.

## Tenancy migration (0023)

Before 0023 every user-facing row was owned by one user (`user_id`), so
each user saw only their own data. 0023:

1. Creates `workspaces` with one row.
2. Adds `users.role` (`admin` | `member`, default `member`),
   `users.must_change_password` and `users.disabled_at`, and makes the
   oldest existing user an admin.
3. Adds `enrollment_tokens.created_by` and `agents.enrolled_by` (both
   `REFERENCES users ON DELETE SET NULL`), backfilled from the old owner.
4. Renames every `user_id` tenant column to `workspace_id` (and
   `image_sbom_state.owner_user_id` to `owner_workspace_id`), points every
   row at the workspace, re-creates the foreign keys (to `workspaces`, and
   the composite tenant keys such as `alert_rule_channels (channel_id,
   workspace_id)`), renames the matching constraints and indexes, and
   rewrites the `mgmt_*` and `image_sbom_effective` / `image_scores`
   functions (`p_user` becomes `p_workspace`). This part is generic: it
   converts every public table with a `user_id` column except Better
   Auth's `sessions` and `accounts`.
5. Deletes rows that would collide once tenants merge, keeping the oldest:
   `host_identities` (same machine id under two users),
   `swarm_clusters` (same cluster id, cascading its services) and agent-sent
   `image_sbom_state` rows. The next agent push re-creates what's needed.
   Nothing is deployed yet, so this loss is acceptable.

The down migration reverses the schema exactly (verified by diffing
`pg_dump --schema-only` before and after up+down) and gives every row to
the oldest admin, since per-user ownership isn't recorded after 0023.

**Why `workspace_id` rather than dropping the scoping**: every query keeps
its shape and parameters (only the value passed changes from the user's
id to the workspace's), the composite tenant foreign keys keep protecting
cross-links, the Go integration tests keep their per-test tenants (each
test creates its own workspace), and a second workspace stays possible
later without another schema rewrite. The app itself only ever uses one:
`getWorkspaceId()` resolves the oldest row. Membership is implicit (every
user belongs to the one workspace), so `users` has no `workspace_id`.

**Enrollment tokens** belong to the workspace; `created_by` records the
admin who issued one, and the agent enrolled with it inherits the
workspace and records `enrolled_by`. Removing that admin keeps the token
and the agent.

## Security notes

- Hidden buttons are UX only; `requireAdmin()` in each action is the
  control. Direct calls to every write action with a member's session were
  checked end to end (see the PR's test plan).
- Server action errors from `requireAdmin()` are thrown in
  `notification-actions.ts` and `actions.ts` (production masks the message
  as a digest) and returned as `{ ok: false }` in the manage and members
  actions.
- A member can still call Better Auth's own user endpoints for their own
  account (`update-user` for name/image, `change-password`). `role`,
  `must_change_password` and `disabled_at` aren't Better Auth fields, so
  they can't be set that way. Changing the password through Better Auth
  directly (not `/change-password`) leaves `must_change_password` set, so
  the user is asked again; harmless.
- Temporary passwords are shown to the admin in clear text so they can be
  passed on; they are hashed like any other (bcrypt) and must be replaced
  at first sign-in.
- Sign-in is rate limited by Better Auth in production.
- Removing a user deletes their sessions and credential; workspace data
  stays.

## Follow-ups

- Invite links / email invites instead of passing a temporary password on
  by hand (needs outbound email for accounts, the SMTP notifier exists).
- Audit log of member and role changes (who changed what).
- Finer roles if asked for (for example an "operator" who can manage hosts
  but not members or channels).
- Empty states for members still describe the admin's next step ("Add
  your first host") without the button; reword them for read-only users.
- Session list and "sign out everywhere" for admins per member.
