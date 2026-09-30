# Single-user tenancy for MVP (no orgs/teams)

**Superseded (2026-09-30)** by [MEMBERS.md](../MEMBERS.md): data now
belongs to one shared workspace per install (`workspace_id`, migration
0023), and users have an Administrator or Member role. Kept for history.

`hosts.user_id` is a direct FK, not `hosts.org_id`. Simplest schema for
launch; adding an organization layer later is a straightforward
migration (`users` → `organizations` → `hosts`) if team customers show
up, and not worth the upfront complexity for a solo founder before
there's demand.
