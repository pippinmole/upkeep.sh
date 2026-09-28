"use client";

import { AlertTriangle, Loader2 } from "lucide-react";
import { useState, useTransition } from "react";

import { createEnrollmentToken } from "@/app/dashboard/actions";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { CopyButton } from "@/components/copy-button";
import {
  DOCKER_SOCKET_MOUNT,
  DockerSocketAlternatives,
  DockerSocketGrant,
} from "@/components/docker-socket-notes";
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

// upkeep-agent-data is the agent's data directory (a folder): its
// credentials.json and its SSH key for remote hosts. Without a persistent
// volume there, the read-only container can't save its credentials.
// withDocker adds the opt-in Docker socket mount
// (docs/decisions/docker-collection.md), the same line as agent/docker-compose.example.yml.
function dockerRunCommand(serverUrl: string, token: string, withDocker: boolean): string {
  const socket = withDocker ? `\n  ${DOCKER_SOCKET_MOUNT} \\` : "";
  return `docker run -d --restart unless-stopped \\
  --pid host --network host --read-only \\
  --cap-drop ALL --security-opt no-new-privileges:true \\
  -v /:/host:ro \\
  -v upkeep-agent-data:/var/lib/upkeep \\${socket}
  -e SW_SERVER_URL=${serverUrl} \\
  -e SW_ENROLLMENT_TOKEN=${token} \\
  ghcr.io/icondesk/upkeep-agent:latest`;
}

// One-time token generation and the agent install command. The panel owns
// its state, so unmounting it (closing the dialog) drops the token: a
// re-open never shows a stale/reusable secret. defaultWithDocker pre-ticks
// the Docker option (opened from a host's Containers / Images tab).
export function EnrollAgentPanel({
  serverUrl,
  defaultWithDocker = false,
}: {
  serverUrl: string;
  defaultWithDocker?: boolean;
}) {
  const [token, setToken] = useState<string | null>(null);
  const [agentName, setAgentName] = useState("");
  const [withDocker, setWithDocker] = useState(defaultWithDocker);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function handleGenerate() {
    setError(null);
    startTransition(async () => {
      try {
        setToken(await createEnrollmentToken(agentName));
      } catch {
        setError("Could not generate a token. Please try again.");
      }
    });
  }

  if (!token) {
    return (
      <div className="flex flex-col gap-4">
        {error && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="agent-name">Agent name (optional)</Label>
          <Input
            id="agent-name"
            value={agentName}
            maxLength={100}
            onChange={(e) => setAgentName(e.target.value)}
            placeholder="Defaults to the host's hostname"
          />
        </div>
        <p className="text-muted-foreground text-sm">
          Click generate to create a one-time token for the new agent. The token expires in 1 hour
          if unused.
        </p>
        <div className="flex justify-end">
          <Button onClick={handleGenerate} disabled={pending}>
            {pending && <Loader2 className="animate-spin" />}
            Generate token
          </Button>
        </div>
      </div>
    );
  }

  const command = dockerRunCommand(serverUrl, token, withDocker);

  return (
    <div className="flex flex-col gap-4">
      <Alert variant="destructive">
        <AlertTriangle className="h-4 w-4" />
        <AlertTitle>Copy this now</AlertTitle>
        <AlertDescription>
          This token is shown only once and can&apos;t be retrieved again. If you lose it, close
          this dialog and register a new agent to get a fresh token.
        </AlertDescription>
      </Alert>

      <div className="flex flex-col gap-1.5">
        <Label htmlFor="enrollment-token">Enrollment token</Label>
        <div className="relative">
          <Input id="enrollment-token" readOnly value={token} className="pr-12 font-mono text-xs" />
          <CopyButton className="absolute top-1/2 right-1 h-7 w-7 -translate-y-1/2" text={token} />
        </div>
      </div>

      <div className="flex flex-col gap-2">
        <p className="text-sm font-medium">Run the agent</p>
        <p className="text-muted-foreground text-sm">
          Pass the token above to the agent on the host you want to monitor. Docker is one way to
          run it — more install methods may be added later.
        </p>

        <div className="flex flex-col gap-1.5">
          <Label>Option: Docker</Label>
          <DockerCollectionOption checked={withDocker} onChange={setWithDocker} />
          <div className="relative">
            <pre className="bg-muted overflow-x-auto rounded-md border p-3 pr-12 text-xs">
              {command}
            </pre>
            <CopyButton className="absolute top-2 right-2 h-7 w-7" text={command} />
          </div>
          <p className="text-muted-foreground text-xs">
            The <code>upkeep-agent-data</code> volume keeps the agent&apos;s credentials and its SSH
            key for remote hosts. Keep it when upgrading or re-creating the container.
          </p>
        </div>
      </div>

      <p className="text-muted-foreground text-sm">
        The agent appears on the Agents page once it enrolls, and its host shows up on the Hosts
        page after the first push.
      </p>
    </div>
  );
}

// Opt-in Docker collection: adds the socket mount to the command. Off by
// default because socket access is root on the host; the copy says so
// plainly (docs/decisions/docker-collection.md).
function DockerCollectionOption({
  checked,
  onChange,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <div className="flex flex-col gap-1.5 rounded-md border p-3">
      <label className="flex items-center gap-2 text-sm font-medium">
        <input
          type="checkbox"
          className="accent-primary size-4"
          checked={checked}
          onChange={(e) => onChange(e.target.checked)}
        />
        Collect Docker containers and images
      </label>
      <p className="text-muted-foreground text-xs">
        <DockerSocketGrant />
      </p>
      {checked && <DockerSocketAlternatives />}
    </div>
  );
}

// "Register agent" on the Agents page. The Hosts page's "Add host" offers
// the same panel as its "install the agent on this machine" option, and a
// remote host's Containers / Images tabs open it to install an agent there.
export function RegisterAgentDialog({
  serverUrl,
  triggerLabel = "Register agent",
  triggerVariant = "default",
  defaultWithDocker = false,
}: {
  serverUrl: string;
  triggerLabel?: string;
  triggerVariant?: "default" | "outline";
  defaultWithDocker?: boolean;
}) {
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant={triggerVariant}>{triggerLabel}</Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Register a new agent</DialogTitle>
          <DialogDescription>
            Generate a one-time enrollment token and run it on the host you want to monitor.
          </DialogDescription>
        </DialogHeader>
        <EnrollAgentPanel serverUrl={serverUrl} defaultWithDocker={defaultWithDocker} />
      </DialogContent>
    </Dialog>
  );
}
