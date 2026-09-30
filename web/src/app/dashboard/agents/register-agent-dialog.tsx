"use client";

import { AlertTriangle, CheckCircle2, Loader2 } from "lucide-react";
import Link from "next/link";
import { useEffect, useState, useTransition } from "react";

import {
  type EnrollmentStatus,
  getEnrollmentStatus,
  issueEnrollmentToken,
} from "@/app/dashboard/actions";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { CopyButton } from "@/components/copy-button";
import {
  DOCKER_SOCKET_MOUNT,
  DockerSocketAlternatives,
  DockerSocketGrant,
} from "@/components/docker-socket-notes";
import { HOST_MOUNTS } from "@/lib/host-mounts";
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
import { adminOnly } from "@/components/viewer-context";

const POLL_MS = 3000;

// upkeep-agent-data is the agent's data directory (a folder): its
// credentials.json and its SSH key for remote hosts. Without a persistent
// volume there, the read-only container can't save its credentials.
// withDocker adds the opt-in Docker socket mount
// (docs/decisions/docker-collection.md), the same line as agent/docker-compose.example.yml.
// image comes from issueEnrollmentToken (lib/agent-image.ts), never
// hard-coded here.
export function dockerRunCommand(
  serverUrl: string,
  token: string,
  withDocker: boolean,
  image: string,
): string {
  const socket = withDocker ? `\n  ${DOCKER_SOCKET_MOUNT} \\` : "";
  const hostMounts = HOST_MOUNTS.map((m) => `  ${m} \\`).join("\n");
  return `docker run -d --restart unless-stopped \\
  --pid host --network host --read-only \\
  --cap-drop ALL --security-opt no-new-privileges:true \\
${hostMounts}
  -v upkeep-agent-data:/var/lib/upkeep \\${socket}
  -e SW_SERVER_URL=${serverUrl} \\
  -e SW_ENROLLMENT_TOKEN=${token} \\
  ${image}`;
}

// One-time token generation, the agent install command, then live progress
// (polled): waiting for the agent, enrolled and waiting for its first
// report, connected. The panel owns its state, so unmounting it (closing
// the dialog) drops the token: a re-open never shows a stale/reusable
// secret. defaultWithDocker pre-ticks the Docker option (opened from a
// host's Containers / Images tab).
export function EnrollAgentPanel({
  serverUrl,
  defaultWithDocker = false,
}: {
  serverUrl: string;
  defaultWithDocker?: boolean;
}) {
  const [issued, setIssued] = useState<{
    token: string;
    issuedAt: string;
    agentImage: string;
  } | null>(null);
  const [agentName, setAgentName] = useState("");
  const [withDocker, setWithDocker] = useState(defaultWithDocker);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function handleGenerate() {
    setError(null);
    startTransition(async () => {
      try {
        setIssued(await issueEnrollmentToken(agentName));
      } catch {
        setError("Could not generate a token. Please try again.");
      }
    });
  }

  if (!issued) {
    return (
      <div className="flex flex-col gap-4">
        {error && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        <p className="text-muted-foreground text-sm">
          The agent is a small container that reads the machine and reports read-only facts to
          upkeep, outbound only. It enrolls with a one-time token that expires in 1 hour if unused.
        </p>
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
        <div className="flex justify-end">
          <Button onClick={handleGenerate} disabled={pending}>
            {pending && <Loader2 className="animate-spin" />}
            Generate install command
          </Button>
        </div>
      </div>
    );
  }

  const { token, issuedAt, agentImage } = issued;
  const command = dockerRunCommand(serverUrl, token, withDocker, agentImage);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-2">
        <p className="text-sm font-medium">Run this on the machine you want to monitor</p>
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

      <div className="border-warning/40 bg-warning/10 flex gap-3 rounded-lg border px-4 py-3 text-sm">
        <AlertTriangle className="text-warning-fg mt-0.5 size-4 shrink-0" aria-hidden />
        <div className="flex flex-col gap-1">
          <p className="text-warning-fg font-medium">Copy this now</p>
          <p className="text-muted-foreground">
            The token in the command is shown only once. If you lose it, close this dialog and
            generate a new one.
          </p>
        </div>
      </div>

      <details className="text-sm">
        <summary className="text-muted-foreground hover:text-foreground cursor-pointer">
          Show token only
        </summary>
        <div className="mt-2 flex flex-col gap-1.5">
          <Label htmlFor="enrollment-token">Enrollment token</Label>
          <div className="relative">
            <Input
              id="enrollment-token"
              readOnly
              value={token}
              className="pr-12 font-mono text-xs"
            />
            <CopyButton
              className="absolute top-1/2 right-1 h-7 w-7 -translate-y-1/2"
              text={token}
            />
          </div>
        </div>
      </details>

      <EnrollmentProgress token={token} issuedAt={issuedAt} />
    </div>
  );
}

// Polls getEnrollmentStatus until the agent's host is reporting or the
// token expires.
function EnrollmentProgress({ token, issuedAt }: { token: string; issuedAt: string }) {
  const [status, setStatus] = useState<EnrollmentStatus>({ state: "waiting" });
  const done = status.state === "reporting" || status.state === "expired";

  useEffect(() => {
    if (done) return;
    let cancelled = false;
    const load = async () => {
      const s = await getEnrollmentStatus(token, issuedAt).catch(() => undefined);
      if (!cancelled && s !== undefined) setStatus(s);
    };
    const id = setInterval(load, POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [token, issuedAt, done]);

  if (status.state === "reporting") {
    return (
      <div
        role="status"
        className="border-success/40 bg-success/10 flex flex-col gap-3 rounded-lg border px-4 py-3 text-sm"
      >
        <p className="flex items-center gap-2 font-medium">
          <CheckCircle2 className="text-success-fg size-4 shrink-0" aria-hidden />
          Connected: {status.hostname} is reporting
        </p>
        <div className="flex flex-wrap gap-2">
          <Button asChild size="sm">
            <Link href={`/dashboard/hosts/${status.hostId}`}>Open host</Link>
          </Button>
          <Button asChild size="sm" variant="outline">
            <Link href="/dashboard/alerts">Next: set up alerts</Link>
          </Button>
        </div>
      </div>
    );
  }
  if (status.state === "expired") {
    return (
      <p role="status" className="text-muted-foreground text-sm">
        This token expired before an agent used it. Close this dialog and generate a new one.
      </p>
    );
  }
  return (
    <div
      role="status"
      className="text-muted-foreground flex items-center gap-2 rounded-lg border px-4 py-3 text-sm"
    >
      <Loader2 className="size-4 shrink-0 animate-spin" aria-hidden />
      {status.state === "enrolled" ? (
        <span>
          Agent <span className="text-foreground font-medium">{status.agentName}</span> enrolled,
          waiting for its first report…
        </span>
      ) : (
        <span>Waiting for the agent to connect…</span>
      )}
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

// "Install an agent" on the Agents page. The Hosts page's "Add host" offers
// the same panel as its "install the agent on this machine" option, and a
// remote host's Containers / Images tabs open it to install an agent there.
function RegisterAgentDialogControl({
  serverUrl,
  triggerLabel = "Install an agent",
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
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Install the agent</DialogTitle>
          <DialogDescription>Run the agent on the machine you want to monitor.</DialogDescription>
        </DialogHeader>
        <EnrollAgentPanel serverUrl={serverUrl} defaultWithDocker={defaultWithDocker} />
      </DialogContent>
    </Dialog>
  );
}

// Write controls: admins only (docs/MEMBERS.md); the server re-checks.
export const RegisterAgentDialog = adminOnly(RegisterAgentDialogControl);
