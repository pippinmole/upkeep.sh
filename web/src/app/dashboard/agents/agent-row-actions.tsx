"use client";

import { Ban, KeyRound, MoreHorizontal } from "lucide-react";
import { useState } from "react";

import { requestAgentRotation, revokeAgent } from "@/app/dashboard/manage-actions";
import { ActionDialog } from "@/components/action-dialog";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { AgentWithHosts } from "@/lib/queries";
import { formatDate } from "@/lib/time";

// Per-agent actions: request a credential rotation (the agent rotates on
// its next push; PROTOCOL.md "Credential rotation") and revoke.
export function AgentRowActions({ agent }: { agent: AgentWithHosts }) {
  const [dialog, setDialog] = useState<"rotate" | "revoke" | null>(null);
  const revoked = agent.status === "revoked";
  const set = (d: typeof dialog) => (open: boolean) => setDialog(open ? d : null);

  return (
    <>
      <DropdownMenu modal={false}>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            className="size-7"
            aria-label={`Actions for ${agent.name}`}
          >
            <MoreHorizontal className="size-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-52">
          <DropdownMenuLabel className="truncate">{agent.name}</DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem
            disabled={revoked || !!agent.rotateRequestedAt}
            onSelect={() => setDialog("rotate")}
          >
            <KeyRound />
            {agent.rotateRequestedAt ? "Rotation pending" : "Rotate credentials"}
          </DropdownMenuItem>
          <DropdownMenuItem
            disabled={revoked}
            onSelect={() => setDialog("revoke")}
            className="text-destructive focus:text-destructive"
          >
            <Ban />
            Revoke agent
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <ActionDialog
        open={dialog === "rotate"}
        onOpenChange={set("rotate")}
        title={`Rotate credentials for ${agent.name}?`}
        description={
          <>
            <p>
              The agent gets a new secret the next time it reports in
              {agent.pushIntervalSeconds
                ? ` (every ${Math.round(agent.pushIntervalSeconds / 60) || 1} min)`
                : ""}
              , and saves it to its <code>credentials.json</code>. Nothing on the host is executed:
              the agent asks for the new secret itself.
            </p>
            <p>
              The old secret stops working once the new one is used, or an hour after the rotation
              at the latest.
              {agent.credentialIssuedAt &&
                ` The current secret was issued on ${formatDate(agent.credentialIssuedAt)}.`}
            </p>
            <p>Agents older than this feature ignore the request; it stays pending.</p>
          </>
        }
        actionLabel="Rotate on next push"
        run={() => requestAgentRotation(agent.id)}
      />
      <ActionDialog
        open={dialog === "revoke"}
        onOpenChange={set("revoke")}
        title={`Revoke ${agent.name}?`}
        description={
          <>
            <p>
              The agent&apos;s credential is refused from now on: its pushes are rejected and its
              hosts stop updating. This can&apos;t be undone; to monitor the machine again, register
              a new agent on it (it re-attaches to the existing host and its history).
            </p>
            <p>Hosts and their history are kept. Stop or remove the agent container yourself.</p>
          </>
        }
        actionLabel="Revoke agent"
        destructive
        run={() => revokeAgent(agent.id)}
      />
    </>
  );
}
