import { Activity } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { tableStateFromParams } from "@/components/data-table/url-params";
import { EmptyState } from "@/components/empty-state";
import { Button } from "@/components/ui/button";
import { MCP_ACTIVITY_TABLE, MCP_CALL_RETENTION_DAYS } from "@/lib/mcp-activity-table";
import {
  getMcpActivity,
  getMcpActivityFacets,
  mcpActivityFilters,
} from "@/lib/queries-mcp-activity";
import type { SearchParams } from "@/lib/search-params";
import { requireViewer } from "@/lib/viewer";

import { INTEGRATIONS_URL } from "../links";
import { ActivityTable } from "./activity-table";

export const metadata: Metadata = { title: "MCP activity" };

// The MCP call log (docs/MCP.md#activity-log): every tool call an app made,
// newest first. Admins see everyone's, members their own
// (queries-mcp-activity.ts enforces it).
export default async function ActivityPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const viewer = await requireViewer();
  const state = tableStateFromParams(await searchParams, MCP_ACTIVITY_TABLE);
  const [{ rows, total }, facets] = await Promise.all([
    getMcpActivity(viewer, mcpActivityFilters(state)),
    getMcpActivityFacets(viewer),
  ]);

  if (facets.tools.length === 0) {
    return (
      <EmptyState
        icon={Activity}
        size="section"
        title="No calls yet"
        description={
          viewer.isAdmin
            ? "Each tool call a connected app makes shows up here, with its arguments and result."
            : "Each tool call your connected apps make shows up here, with its arguments and result."
        }
        action={
          <Button asChild variant="outline">
            <Link href={INTEGRATIONS_URL}>How to connect</Link>
          </Button>
        }
      />
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-muted-foreground text-sm">
        {viewer.isAdmin
          ? "Every tool call apps made on this install."
          : "Every tool call your apps made."}{" "}
        Calls are kept for {MCP_CALL_RETENTION_DAYS} days.
      </p>
      <ActivityTable
        rows={rows}
        total={total}
        state={state}
        facets={facets}
        isAdmin={viewer.isAdmin}
        currentUserId={viewer.userId}
      />
    </div>
  );
}
