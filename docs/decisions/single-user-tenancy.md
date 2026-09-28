# Single-user tenancy for MVP (no orgs/teams)

`hosts.user_id` is a direct FK, not `hosts.org_id`. Simplest schema for
launch; adding an organization layer later is a straightforward
migration (`users` → `organizations` → `hosts`) if team customers show
up, and not worth the upfront complexity for a solo founder before
there's demand.
