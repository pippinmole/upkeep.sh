// Ownership for every "Needs attention" provider query, in one place.
// Provider SQL never names the tenant column: it filters with owned() or
// activeHost(), and the runner (index.ts) binds the viewer's workspace id
// to $1.
const OWNER_COLUMN = "workspace_id";

// `<alias>` belongs to the workspace.
export function owned(alias: string): string {
  return `${alias}.${OWNER_COLUMN} = $1`;
}

// `<alias>` is one of the workspace's hosts that isn't archived.
export function activeHost(alias = "h"): string {
  return `${owned(alias)} AND ${alias}.archived_at IS NULL`;
}
