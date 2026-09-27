"use client";

import { ArrowLeft, Loader2, Network, Server } from "lucide-react";
import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { CollectorAgent } from "@/lib/queries-remote";

import { EnrollAgentPanel } from "../agents/register-agent-dialog";
import { addRemoteHost } from "../manage-actions";
import { RemoteTargetPanel } from "./remote-target-panel";

type Step =
  | { kind: "choose" }
  | { kind: "local" }
  | { kind: "remote" }
  | { kind: "setup"; agentId: string; hostId: string };

const TITLES: Record<Step["kind"], [string, string]> = {
  choose: ["Add a host", "How should upkeep reach the machine?"],
  local: ["Install the agent", "Run the agent on the machine you want to monitor."],
  remote: [
    "Reach it from an agent",
    "An agent on the same network reads the host over SSH (read-only SFTP).",
  ],
  setup: ["Connect the host", "Authorize the agent and confirm the host's identity."],
};

// "Add host" on the Hosts page (DOMAIN_MODEL.md §4.2): either install an
// agent on the machine itself, or have an existing agent reach it over
// SSH. State lives in the content, which unmounts on close, so every open
// starts at the choice.
export function AddHostDialog({
  serverUrl,
  agents,
}: {
  serverUrl: string;
  agents: CollectorAgent[];
}) {
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button>Add host</Button>
      </DialogTrigger>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-xl">
        <AddHostFlow serverUrl={serverUrl} agents={agents} />
      </DialogContent>
    </Dialog>
  );
}

function AddHostFlow({ serverUrl, agents }: { serverUrl: string; agents: CollectorAgent[] }) {
  const [step, setStep] = useState<Step>({ kind: "choose" });
  const [title, description] = TITLES[step.kind];
  // No way back from "setup": the host already exists by then.
  const canGoBack = step.kind === "local" || step.kind === "remote";

  return (
    <>
      <DialogHeader>
        <div className="flex items-center justify-center gap-1 sm:justify-start">
          {canGoBack && (
            <Button
              variant="ghost"
              size="icon-sm"
              className="-ml-1"
              aria-label="Back"
              title="Back"
              onClick={() => setStep({ kind: "choose" })}
            >
              <ArrowLeft />
            </Button>
          )}
          <DialogTitle>{title}</DialogTitle>
        </div>
        <DialogDescription>{description}</DialogDescription>
      </DialogHeader>

      {step.kind === "choose" && (
        <div className="grid gap-3 sm:grid-cols-2">
          <ChoiceCard
            icon={<Server className="size-5" />}
            title="Install the agent on it"
            body="Run the agent on the machine. It reports everything, including live ports and processes."
            onClick={() => setStep({ kind: "local" })}
          />
          <ChoiceCard
            icon={<Network className="size-5" />}
            title="Reach it from an existing agent"
            body="For machines you'd rather not install on. An agent on the same network reads it over SSH."
            onClick={() => setStep({ kind: "remote" })}
          />
        </div>
      )}

      {step.kind === "local" && <EnrollAgentPanel serverUrl={serverUrl} />}

      {step.kind === "remote" && (
        <RemoteHostForm
          agents={agents}
          onAdded={(agentId, hostId) => setStep({ kind: "setup", agentId, hostId })}
        />
      )}

      {step.kind === "setup" && <RemoteTargetPanel agentId={step.agentId} hostId={step.hostId} />}
    </>
  );
}

function ChoiceCard({
  icon,
  title,
  body,
  onClick,
}: {
  icon: React.ReactNode;
  title: string;
  body: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="hover:bg-accent focus-visible:ring-ring flex flex-col items-start gap-2 rounded-lg border p-4 text-left transition-colors focus-visible:ring-2 focus-visible:outline-hidden"
    >
      <span className="text-muted-foreground">{icon}</span>
      <span className="font-medium">{title}</span>
      <span className="text-muted-foreground text-sm">{body}</span>
    </button>
  );
}

function RemoteHostForm({
  agents,
  onAdded,
}: {
  agents: CollectorAgent[];
  onAdded: (agentId: string, hostId: string) => void;
}) {
  const online = agents.find((a) => a.status === "online");
  const [agentId, setAgentId] = useState(online?.id ?? agents[0]?.id ?? "");
  const [address, setAddress] = useState("");
  const [port, setPort] = useState("22");
  const [username, setUsername] = useState("upkeep");
  const [label, setLabel] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  if (agents.length === 0) {
    return (
      <p className="text-muted-foreground text-sm">
        You don&apos;t have an agent yet. Install one on a machine on the same network as the host
        (&quot;Install the agent on it&quot;), then come back here.
      </p>
    );
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    startTransition(async () => {
      const res = await addRemoteHost({
        agentId,
        address: address.trim(),
        port: Number(port),
        username: username.trim(),
        label: label.trim(),
      });
      if (res.ok) onAdded(agentId, res.hostId);
      else setError(res.error);
    });
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="remote-agent">Agent</Label>
        <Select value={agentId} onValueChange={setAgentId}>
          <SelectTrigger id="remote-agent">
            <SelectValue placeholder="Choose an agent" />
          </SelectTrigger>
          <SelectContent>
            {agents.map((a) => (
              <SelectItem key={a.id} value={a.id}>
                {a.name}
                {a.status !== "online" && (
                  <span className="text-muted-foreground"> ({a.status})</span>
                )}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <p className="text-muted-foreground text-xs">
          It must be able to reach the host&apos;s SSH port.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-[1fr_6rem]">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="remote-address">IP address or DNS name</Label>
          <Input
            id="remote-address"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="10.0.0.12 or db-1.internal"
            maxLength={253}
            required
            autoComplete="off"
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="remote-port">SSH port</Label>
          <Input
            id="remote-port"
            type="number"
            min={1}
            max={65535}
            value={port}
            onChange={(e) => setPort(e.target.value)}
            required
          />
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="remote-user">Username</Label>
          <Input
            id="remote-user"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            maxLength={32}
            required
            autoComplete="off"
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="remote-label">Display name (optional)</Label>
          <Input
            id="remote-label"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            maxLength={100}
            placeholder="Defaults to its hostname"
          />
        </div>
      </div>

      {error && <p className="text-destructive text-sm">{error}</p>}

      <div className="flex justify-end">
        <Button type="submit" disabled={pending || !agentId || !address.trim()}>
          {pending && <Loader2 className="animate-spin" />}
          Add host
        </Button>
      </div>
    </form>
  );
}
