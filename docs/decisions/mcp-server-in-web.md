# MCP server in the Next.js app, not the Go API or its own container

Considered, 2026-10-04: where should the MCP server ([MCP.md](../MCP.md)) run: in `web/` (Next.js), in
`server/cmd/api` (Go), or as a separate container?

**Decided: in `web/`, as a route handler at `/api/mcp`**, using the official MCP TypeScript SDK (v2, stateless
Streamable HTTP).

1. **The queries already live there.** The tools are the dashboard's reads with a different output format:
   `lib/queries-vuln-list.ts`, `queries-vulns.ts`, `queries-image-vulns.ts`, `queries-overview.ts`,
   `attention/`. Building them in Go would mean porting that SQL and keeping two copies in step.
2. **User auth and roles already live there.** Better Auth, `lib/viewer.ts`, `requireAdmin` and the workspace
   scoping are all in `web/`. The Go API only knows agent credentials; teaching it to verify user sessions or
   OAuth tokens is a new trust boundary for no gain.
3. **It keeps the Go API's job narrow.** `cmd/api` is the agent protocol, deliberately not a general API
   ([ingest-api-in-go.md](ingest-api-in-go.md), [direct-postgres-reads.md](direct-postgres-reads.md)). An MCP
   server is a dashboard client in a different shape, not agent protocol.
4. **Writes follow the existing
   [ownership table](../ARCHITECTURE.md#who-owns-what-avoiding-split-brain-writes).** When write tools come,
   dashboard-owned tables are written by Next.js as now, and work for the worker is a River job, which `web/`
   already inserts (`lib/river.ts`).
5. **A separate container buys nothing yet.** It would need its own copy of the auth and the queries, or would
   call into one of the other two. If the MCP traffic ever needs scaling or isolating from the dashboard, run
   the same `web` image as a second service and route `/api/mcp` to it, rather than starting a new codebase.

**Path:** `/api/mcp` on the dashboard's domain, next to `/api/auth`. One origin for the MCP endpoint and the
OAuth authorization server keeps discovery simple, and there's no extra domain to point in Dokploy.

**Cost:** MCP traffic shares the dashboard's Node process. Tool calls are the same queries as page renders,
capped at 100 items, so the load is comparable to a user clicking around; the per-credential rate limit
([MCP.md](../MCP.md#security-notes)) bounds an agent stuck in a loop.
