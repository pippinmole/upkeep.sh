import { Plug } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { EmptyState } from "@/components/empty-state";
import { Button } from "@/components/ui/button";
import { getConnectedApps } from "@/lib/queries-integrations";
import { requireViewer } from "@/lib/viewer";

import { INTEGRATIONS_URL } from "../links";
import { ConnectedAppsTable } from "./connected-apps-table";

export const metadata: Metadata = { title: "Connected apps" };

// The OAuth clients users have allowed to read the workspace. Admins see
// and revoke everyone's; members their own (getConnectedApps and the
// revoke action enforce it).
export default async function ConnectedAppsPage() {
  const viewer = await requireViewer();
  const apps = await getConnectedApps(viewer);

  return (
    <div className="flex flex-col gap-4">
      <p className="text-muted-foreground text-sm">
        {viewer.isAdmin
          ? "Apps anyone on this install has allowed to read the workspace. Revoking one signs it out: its next call fails and it has to ask again."
          : "Apps you've allowed to read the workspace. Revoking one signs it out: its next call fails and it has to ask again."}
      </p>
      {apps.length === 0 ? (
        <EmptyState
          icon={Plug}
          size="section"
          title="No connected apps"
          description={
            viewer.isAdmin
              ? "Nobody has connected an app yet. Once someone signs in to Claude Code with this install, it shows up here."
              : "Once you sign in to Claude Code with this install, it shows up here."
          }
          action={
            <Button asChild variant="outline">
              <Link href={INTEGRATIONS_URL}>How to connect</Link>
            </Button>
          }
        />
      ) : (
        <ConnectedAppsTable apps={apps} isAdmin={viewer.isAdmin} currentUserId={viewer.userId} />
      )}
    </div>
  );
}
