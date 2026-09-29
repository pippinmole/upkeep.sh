"use client";

import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import type { HostAgent } from "@/lib/queries";

import { RemoteTargetPanel } from "./remote-target-panel";

// What a remote assignment needs, for the Hosts list badge; null when it
// is healthy.
function attention(a: HostAgent): { label: string; urgent: boolean } | null {
  if (a.mode === "local") return null;
  if (a.errorCode === "host_key_mismatch") return { label: "Host key changed", urgent: true };
  if (a.keyPending) return { label: "Confirm host key", urgent: false };
  if (a.errorCode) return { label: "Can't connect", urgent: true };
  if (!a.collected) return { label: "Finish setup", urgent: false };
  return null;
}

// Hosts list: a badge on a remote host's agent that opens its setup and
// connection panel.
export function RemoteTargetBadge({ agent, hostId }: { agent: HostAgent; hostId: string }) {
  const need = attention(agent);
  if (!need) return null;
  return (
    <Dialog>
      <DialogTrigger asChild>
        <button type="button" className="text-left">
          <Badge variant={need.urgent ? "danger" : "warning"}>{need.label}</Badge>
        </button>
      </DialogTrigger>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Remote host</DialogTitle>
          <DialogDescription>Connection from {agent.name} over SSH.</DialogDescription>
        </DialogHeader>
        <RemoteTargetPanel agentId={agent.id} hostId={hostId} />
      </DialogContent>
    </Dialog>
  );
}
