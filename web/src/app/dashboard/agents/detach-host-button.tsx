"use client";

import { Unlink } from "lucide-react";
import { useState } from "react";

import { detachHost } from "@/app/dashboard/manage-actions";
import { ActionDialog } from "@/components/action-dialog";
import { Button } from "@/components/ui/button";
import type { AgentHostRow, AgentWithHosts } from "@/lib/queries";
import { adminOnly } from "@/components/viewer-context";

// Remove an inactive (revoked or stale) agent's assignment to a host, e.g.
// the old agent left on a host after a reinstall was merged into it.
function DetachHostButtonControl({ agent, host }: { agent: AgentWithHosts; host: AgentHostRow }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        className="text-muted-foreground h-7"
        onClick={() => setOpen(true)}
      >
        <Unlink className="size-3.5" />
        Detach
      </Button>
      <ActionDialog
        open={open}
        onOpenChange={setOpen}
        title={`Detach ${host.hostname} from ${agent.name}?`}
        description={
          <>
            <p>
              {agent.name} will no longer be listed as collecting {host.hostname}. The host, its
              history and its other agents are not affected.
            </p>
            <p>
              If this agent starts reporting again, its next push is treated as a first push and
              attaches it to a host by machine identity again.
            </p>
          </>
        }
        actionLabel="Detach"
        run={() => detachHost(agent.id, host.hostId)}
      />
    </>
  );
}

// Write controls: admins only (docs/MEMBERS.md); the server re-checks.
export const DetachHostButton = adminOnly(DetachHostButtonControl);
