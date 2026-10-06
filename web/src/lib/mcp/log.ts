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
  const cred = viewer.credential;
  try {
    await pool.query(
      `INSERT INTO mcp_calls (workspace_id, user_id, credential_kind, oauth_client_id, api_token_id,
                              client_name, tool, arguments, result_items, duration_ms, error)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [
        viewer.workspaceId,
        viewer.userId,
        cred.kind,
        // Only the credential kind's own reference (mcp_calls_credential_ref_check).
        cred.kind === "oauth" ? cred.oauthClientId : null,
        cred.kind === "api_token" ? cred.apiTokenId : null,
        cred.clientName,
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
