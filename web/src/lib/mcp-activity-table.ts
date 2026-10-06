import type { TableUrlOptions } from "@/components/data-table/url-params";

// URL state of Settings > Integrations > Activity, the MCP call log
// (docs/MCP.md#activity-log), shared by the Server Component (parsing, SQL
// allowlists) and the client table. Client-safe.

export const MCP_ACTIVITY_SORTS = ["time", "tool", "duration"] as const;
export type McpActivitySort = (typeof MCP_ACTIVITY_SORTS)[number];

// Newest first, 50 a page.
export const MCP_ACTIVITY_TABLE: TableUrlOptions = {
  sortKeys: MCP_ACTIVITY_SORTS,
  filterKeys: ["user", "client", "tool"],
  defaultSort: { id: "time", desc: true },
  defaultPageSize: 50,
};

export const MCP_CALL_RETENTION_DAYS = 90;
