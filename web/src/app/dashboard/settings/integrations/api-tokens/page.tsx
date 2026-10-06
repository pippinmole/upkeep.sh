import { KeyRound } from "lucide-react";
import type { Metadata } from "next";

import { EmptyState } from "@/components/empty-state";
import { SectionDescription } from "@/components/layout/page-header";
import { mcpResourceUrl } from "@/lib/auth";
import { getApiTokens } from "@/lib/queries-integrations";
import { requireViewer } from "@/lib/viewer";

import { ApiTokensTable } from "./api-tokens-table";
import { CreateTokenButton } from "./create-token-dialog";

export const metadata: Metadata = { title: "API tokens" };

// Tokens for headless MCP clients (docs/MCP.md#api-tokens-headless-agents):
// everyone creates their own; admins see and revoke everyone's, members
// their own (getApiTokens and the revoke action enforce it).
export default async function ApiTokensPage() {
  const viewer = await requireViewer();
  const tokens = await getApiTokens(viewer);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <SectionDescription>
          {viewer.isAdmin
            ? "Tokens let an agent without a browser, such as claude -p in cron or CI, read the workspace with its owner's permissions. Everyone's tokens are listed here; revoking one makes its next call fail."
            : "Tokens let an agent without a browser, such as claude -p in cron or CI, read the workspace with your permissions. Revoking one makes its next call fail."}
        </SectionDescription>
        {/* Always here, never in the empty state: creating the first token
            revalidates the page into the table, and the dialog (with the
            one-time reveal) must stay mounted through that. */}
        <CreateTokenButton mcpUrl={mcpResourceUrl()} />
      </div>
      {tokens.length === 0 ? (
        <EmptyState
          icon={KeyRound}
          size="section"
          title="No API tokens"
          description={
            viewer.isAdmin
              ? "Nobody has created a token yet. Each token is shown once, when it's created."
              : "Create one for a headless agent. It's shown once, when it's created."
          }
        />
      ) : (
        <ApiTokensTable tokens={tokens} isAdmin={viewer.isAdmin} currentUserId={viewer.userId} />
      )}
    </div>
  );
}
