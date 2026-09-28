# Postgres 18's data directory mount

Postgres 18's official image switched to a pg_ctlcluster-style layout
and expects a single volume mount at `/var/lib/postgresql` (not
`/var/lib/postgresql/data` as in older images) — mounting at the old path
causes the container to refuse to start. Both compose files mount
`pgdata:/var/lib/postgresql` accordingly. If you ever pin back to an
older Postgres major, check whether this needs reverting.
