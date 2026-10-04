import { pool } from "@/lib/db";
import type { McpViewer } from "@/lib/viewer";

// One row per tool call in mcp_calls (docs/MCP.md#activity-log). Read tools
// log best effort: a failed insert is reported to the server log and the
// call still returns.

export type McpCallRecord = {
  viewer: McpViewer;
  tool: string;
  arguments: unknown;
  resultItems: number | null;
  durationMs: number;
  error: string | null;
};

export type McpCallLogger = (call: McpCallRecord) => Promise<void>;

export const logMcpCall: McpCallLogger = async (call) => {
  const { viewer } = call;
  try {
    await pool.query(
      `INSERT INTO mcp_calls (workspace_id, user_id, credential_kind, oauth_client_id, client_name,
                              tool, arguments, result_items, duration_ms, error)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        viewer.workspaceId,
        viewer.userId,
        viewer.credential.kind,
        viewer.credential.oauthClientId,
        viewer.credential.clientName,
        call.tool,
        JSON.stringify(call.arguments ?? {}),
        call.resultItems,
        Math.round(call.durationMs),
        call.error,
      ],
    );
  } catch (err) {
    console.error(`mcp: logging the ${call.tool} call failed`, err);
  }
};
