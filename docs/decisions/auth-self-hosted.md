# Auth: self-hosted Better Auth, not a managed vendor (Clerk/Auth0)

Fits the project's self-hosted, no-vendor-sprawl pitch — a security
monitoring tool that itself depends on a third-party auth vendor is a
harder sell. Cost: we own session/password security rather than
offloading it.

Better Auth is a library running inside the Next.js app, against our own
Postgres: username + password sign-in (its `username` plugin, email kept
for the account), bcrypt cost 12 password hashes, and database sessions
(a `sessions` row per signed-in browser, cookie signed with
`BETTER_AUTH_SECRET`) that can be listed and revoked, unlike the
stateless JWTs we had before. Its `user` model is mapped onto our existing
`users` table so every `users(id)` foreign key is untouched
(migrations/0018_better_auth).

Replaced Auth.js (next-auth v5, still beta, Credentials provider, JWT
sessions): the credentials path there is deliberately second-class, and
Better Auth gives sessions, usernames and future methods (2FA, passkeys,
OAuth) as plugins without leaving our database.
