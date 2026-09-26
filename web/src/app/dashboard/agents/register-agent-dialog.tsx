"use client";

import { AlertTriangle, Loader2 } from "lucide-react";
import { useState, useTransition } from "react";

import { createEnrollmentToken } from "@/app/dashboard/actions";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { CopyButton } from "@/components/copy-button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

function dockerRunCommand(serverUrl: string, token: string): string {
  return `docker run -d --restart unless-stopped \\
  --pid host --network host --read-only \\
  --cap-drop ALL --security-opt no-new-privileges:true \\
  -v /:/host:ro \\
  -e SW_SERVER_URL=${serverUrl} \\
  -e SW_ENROLLMENT_TOKEN=${token} \\
  ghcr.io/icondesk/security-whatnot-agent:latest`;
}

export function RegisterAgentDialog({ serverUrl }: { serverUrl: string }) {
  const [open, setOpen] = useState(false);
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  // Reset all local state whenever the dialog closes (including the
  // generated token) so a re-open never shows a stale/reusable secret —
  // the only way to see a valid token is to generate a fresh one.
  function handleOpenChange(next: boolean) {
    setOpen(next);
    if (!next) {
      setToken(null);
      setError(null);
    }
  }

  function handleGenerate() {
    setError(null);
    startTransition(async () => {
      try {
        setToken(await createEnrollmentToken());
      } catch {
        setError("Could not generate a token. Please try again.");
      }
    });
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>
        <Button>Register agent</Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Register a new agent</DialogTitle>
          <DialogDescription>
            Generate a one-time enrollment token and run it on the host you
            want to monitor.
          </DialogDescription>
        </DialogHeader>

        {!token ? (
          <div className="flex flex-col gap-4">
            {error && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            <p className="text-muted-foreground text-sm">
              Click generate to create a one-time token for the new host. The
              token expires in 1 hour if unused.
            </p>
          </div>
        ) : (
          <div className="flex flex-col gap-4">
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>Copy this now</AlertTitle>
              <AlertDescription>
                This token is shown only once and can&apos;t be retrieved
                again. If you lose it, close this dialog and register a new
                agent to get a fresh token.
              </AlertDescription>
            </Alert>

            <div className="flex flex-col gap-1.5">
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

            <div className="flex flex-col gap-2">
              <p className="text-sm font-medium">Run the agent</p>
              <p className="text-muted-foreground text-sm">
                Pass the token above to the agent on the host you want to
                monitor. Docker is one way to run it — more install methods
                may be added later.
              </p>

              <div className="flex flex-col gap-1.5">
                <Label>Option: Docker</Label>
                <div className="relative">
                  <pre className="bg-muted overflow-x-auto rounded-md border p-3 pr-12 text-xs">
                    {dockerRunCommand(serverUrl, token)}
                  </pre>
                  <CopyButton
                    className="absolute top-2 right-2 h-7 w-7"
                    text={dockerRunCommand(serverUrl, token)}
                  />
                </div>
              </div>
            </div>

            <p className="text-muted-foreground text-sm">
              The agent will appear in this list once it checks in.
            </p>
          </div>
        )}

        <DialogFooter>
          {!token && (
            <Button onClick={handleGenerate} disabled={pending}>
              {pending && <Loader2 className="animate-spin" />}
              Generate token
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
