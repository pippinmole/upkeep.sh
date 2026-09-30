# Members and roles

Spec: [MEMBERS.md](../MEMBERS.md). One shared workspace per install,
Administrator / Member roles, admin-created accounts.

- [x] Migration `0023_members`: `workspaces` (one row), `user_id` →
      `workspace_id` on every tenant table (+ `owner_workspace_id`),
      `users.role` / `must_change_password` / `disabled_at`, oldest user
      becomes admin, `enrollment_tokens.created_by`, `agents.enrolled_by`.
      Up/down verified against seeded two-user data.
- [x] Go store, jobs and tests on `workspace_id`; enrollment records the
      token's issuer on the agent.
- [x] Dashboard reads scoped by the install workspace (`lib/viewer.ts`).
- [x] Server-side role checks: every mutating server action calls
      `requireAdmin()`.
- [x] Sign-up only bootstraps the first (admin) account; refused server
      side afterwards (Better Auth endpoint and database hooks).
- [x] Settings > Members (TanStack table): add with temporary password,
      change role, reset password, disable/enable, remove; guard rails
      (not yourself, always one enabled admin).
- [x] Forced password change after a temporary password
      (`/change-password`), also reachable from the user menu.
- [x] Write controls hidden from members (`adminOnly()`).
- [ ] Invite links / email invites instead of hand-passed temporary
      passwords.
- [ ] Audit log of member and role changes.
- [ ] Member-facing copy for empty states that point at admin actions.
