# Direct Postgres reads from Next.js

Considered: should the dashboard read Postgres directly, or go through
the Go API for everything (including reads)?

**Decided: direct reads**, with write ownership split by table (see
[ARCHITECTURE.md](../ARCHITECTURE.md#who-owns-what-avoiding-split-brain-writes)).
Reasoning:

1. No new trust boundary is created — the browser never touches Postgres
   either way; only server-side Next.js code (Server Components, Server
   Actions) would, running in the same private network as the Go API.
2. The Go API's job is agent-protocol + background workers, not general
   CRUD. Dashboard reads (list my hosts, my findings) are plain
   `WHERE user_id = session.user.id` queries — not agent-protocol logic.
3. Building the same CRUD twice (a Go REST surface *and* a typed Next.js
   client for it) is pure overhead for a solo founder, for tables with no
   business logic beyond row ownership.
4. It's the idiomatic Next.js App Router pattern (Server Components
   querying a DB directly via `pg`/Drizzle/Prisma), not a shortcut.

**Caching implication** (raised explicitly — worth preserving): Next.js's
Data Cache only wraps `fetch()`, not raw `pg.query()` calls, so as built
there is no cache to go stale. If caching is added later on a
Go-written table, the correct long-term fix is **not** routing reads
through Go — it's Go calling an on-demand revalidation endpoint in
Next.js after it writes (`POST /api/revalidate?tag=...`), the same
pattern Next.js recommends for any external writer (CMS webhooks, etc.).
This is a durable production pattern, not a stopgap. The real argument
*for* full API-mediation would be a different one — single-writer
enforcement of business rules — which is already handled by the
write-ownership split without needing to route reads through Go too.
