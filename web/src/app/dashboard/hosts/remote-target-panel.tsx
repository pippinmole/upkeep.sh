"use client";

import { AlertTriangle, CheckCircle2, KeyRound, Loader2 } from "lucide-react";
import Link from "next/link";
import { useEffect, useState, useTransition } from "react";

import { CopyButton } from "@/components/copy-button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import type { RemoteTarget } from "@/lib/queries-remote";
import { relativeTime } from "@/lib/time";

import { confirmHostKey, fetchRemoteTarget } from "../manage-actions";

const POLL_MS = 3000;

// The agent's key, locked down to read-only SFTP on the remote side: no
// shell, no forwarding, and sftp-server refuses every write (-R).
function authorizedKeysLine(publicKey: string): string {
  return `restrict,command="/usr/lib/openssh/sftp-server -R" ${publicKey}`;
}

// Safe to re-run: the user is only created when missing and the key line
// only appended when it isn't there yet.
function setupCommands(username: string, publicKey: string): string {
  const home = `/home/${username}`;
  const keys = `${home}/.ssh/authorized_keys`;
  const line = authorizedKeysLine(publicKey);
  return [
    `id -u ${username} >/dev/null 2>&1 || sudo useradd --system --create-home --home-dir ${home} --shell /bin/sh ${username}`,
    `sudo install -d -m 700 -o ${username} -g ${username} ${home}/.ssh`,
    `sudo grep -qxF '${line}' ${keys} 2>/dev/null || echo '${line}' | sudo tee -a ${keys} >/dev/null`,
    `sudo chown ${username}:${username} ${keys}`,
    `sudo chmod 600 ${keys}`,
  ].join("\n");
}

const HOST_KEY_FILE: Record<string, string> = {
  "ssh-ed25519": "ssh_host_ed25519_key.pub",
  "ssh-rsa": "ssh_host_rsa_key.pub",
  "ecdsa-sha2-nistp256": "ssh_host_ecdsa_key.pub",
  "ecdsa-sha2-nistp384": "ssh_host_ecdsa_key.pub",
  "ecdsa-sha2-nistp521": "ssh_host_ecdsa_key.pub",
};

const ERROR_TITLE: Record<string, string> = {
  auth_failed: "The host refused the agent's key",
  unreachable: "The agent can't reach the host",
  sftp_failed: "Connected, but SFTP isn't available",
  push_failed: "Collected, but the push to the server failed",
};

function CodeBlock({ text }: { text: string }) {
  return (
    <div className="relative">
      <pre className="bg-muted overflow-x-auto rounded-md border p-3 pr-12 text-xs whitespace-pre">
        {text}
      </pre>
      <CopyButton className="absolute top-2 right-2 h-7 w-7" text={text} />
    </div>
  );
}

// Setup and connection state of one remote host, refreshed every few
// seconds: authorize the agent's key on the host, confirm the host key
// the agent reported, then wait for the first snapshot.
export function RemoteTargetPanel({
  agentId,
  hostId,
  initial = null,
}: {
  agentId: string;
  hostId: string;
  initial?: RemoteTarget | null;
}) {
  const [target, setTarget] = useState<RemoteTarget | null>(initial);
  const [loaded, setLoaded] = useState(initial !== null);
  const [confirmError, setConfirmError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      const t = await fetchRemoteTarget(agentId, hostId).catch(() => undefined);
      if (cancelled || t === undefined) return;
      setTarget(t);
      setLoaded(true);
    };
    void load();
    const id = setInterval(load, POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [agentId, hostId]);

  if (!loaded) {
    return (
      <div className="text-muted-foreground flex items-center gap-2 text-sm">
        <Loader2 className="size-4 animate-spin" /> Loading…
      </div>
    );
  }
  if (!target) {
    return <p className="text-muted-foreground text-sm">This remote host no longer exists.</p>;
  }

  const t = target;
  const connected = t.lastCollectedAt !== null && t.errorCode === null;
  const mismatch = t.errorCode === "host_key_mismatch";
  const needsKey = t.pendingKey !== null;
  // Once the agent has collected the host its key is in; only an auth
  // failure brings the instructions back.
  const showAuthorize = !connected && (t.lastCollectedAt === null || t.errorCode === "auth_failed");

  function handleConfirm(key: string) {
    setConfirmError(null);
    startTransition(async () => {
      const res = await confirmHostKey(agentId, hostId, key);
      if (!res.ok) setConfirmError(res.error);
      const next = await fetchRemoteTarget(agentId, hostId).catch(() => undefined);
      if (next !== undefined) setTarget(next);
    });
  }

  return (
    <div className="flex flex-col gap-5 text-sm">
      <p className="text-muted-foreground">
        <span className="text-foreground font-medium">{t.agentName}</span> reads{" "}
        <span className="text-foreground font-mono">
          {t.username}@{t.address}:{t.port}
        </span>{" "}
        over read-only SFTP.
        {t.agentStatus !== "online" && (
          <span className="text-warning-fg">
            {" "}
            The agent is {t.agentStatus === "never" ? "not connected yet" : t.agentStatus}, so
            nothing will happen until it reports in.
          </span>
        )}
      </p>

      {connected && (
        <Alert>
          <CheckCircle2 className="h-4 w-4" />
          <AlertTitle>Connected</AlertTitle>
          <AlertDescription>
            Last snapshot {relativeTime(t.lastCollectedAt)}.{" "}
            <Link href={`/dashboard/hosts/${t.hostId}`} className="underline">
              Open {t.label ?? t.hostname}
            </Link>
          </AlertDescription>
        </Alert>
      )}

      {showAuthorize && (
        <section className="flex flex-col gap-2">
          <h3 className="font-medium">1. Authorize the agent on the host</h3>
          {t.agentPublicKey ? (
            <>
              <p className="text-muted-foreground">
                Run this on <span className="font-mono">{t.address}</span>. It creates a{" "}
                <span className="font-mono">{t.username}</span> user if there isn&apos;t one (for an
                existing user, adjust the home directory) and lets the agent&apos;s key in, limited
                to reading files. It&apos;s safe to run again. The agent never runs commands on the
                host.
              </p>
              <CodeBlock text={setupCommands(t.username, t.agentPublicKey)} />
              <p className="text-muted-foreground text-xs">
                On RHEL, Fedora and derivatives the SFTP server is{" "}
                <span className="font-mono">/usr/libexec/openssh/sftp-server</span>.
              </p>
            </>
          ) : (
            <p className="text-muted-foreground">Waiting for the agent to report its SSH key…</p>
          )}
        </section>
      )}

      {needsKey && t.pendingKey && (
        <section className="flex flex-col gap-2">
          <h3 className="flex items-center gap-1.5 font-medium">
            <KeyRound className="size-4" />
            {mismatch ? "The host key changed" : "2. Confirm the host key"}
          </h3>
          {mismatch && (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>Collection is paused</AlertTitle>
              <AlertDescription>
                The host presented a different key than the one you confirmed
                {t.hostKeyFingerprint && (
                  <>
                    {" "}
                    (<span className="font-mono break-all">{t.hostKeyFingerprint}</span>)
                  </>
                )}
                . That is expected after reinstalling the host or regenerating its keys; otherwise
                something may be intercepting the connection.
              </AlertDescription>
            </Alert>
          )}
          <p className="text-muted-foreground">
            The agent reached the host, which presented this key. Check it on the host before
            confirming:
          </p>
          <CodeBlock
            text={`ssh-keygen -lf /etc/ssh/${HOST_KEY_FILE[t.pendingKeyType ?? ""] ?? "ssh_host_ed25519_key.pub"}`}
          />
          <div className="bg-muted/50 rounded-md border p-3 font-mono text-xs break-all">
            {t.pendingFingerprint}
          </div>
          {confirmError && <p className="text-destructive">{confirmError}</p>}
          <div>
            <Button onClick={() => handleConfirm(t.pendingKey!)} disabled={pending}>
              {pending && <Loader2 className="animate-spin" />}
              {mismatch ? "Accept the new key" : "The fingerprint matches"}
            </Button>
          </div>
        </section>
      )}

      {!connected && !needsKey && <StatusLine target={t} />}
    </div>
  );
}

function StatusLine({ target: t }: { target: RemoteTarget }) {
  if (t.errorCode && ERROR_TITLE[t.errorCode]) {
    return (
      <Alert variant="destructive">
        <AlertTriangle className="h-4 w-4" />
        <AlertTitle>{ERROR_TITLE[t.errorCode]}</AlertTitle>
        <AlertDescription>
          {t.error && <span className="font-mono text-xs break-all">{t.error}</span>}
          <span className="block">
            Tried {relativeTime(t.lastAttemptAt)}. The agent retries on its own, sooner right after
            you change something here.
          </span>
        </AlertDescription>
      </Alert>
    );
  }
  return (
    <div className="text-muted-foreground flex items-center gap-2">
      <Loader2 className="size-4 animate-spin" />
      {t.hostKey
        ? "Host key confirmed. Waiting for the agent to connect and send the first snapshot…"
        : "Waiting for the agent to pick up the new host (it checks about once a minute)…"}
    </div>
  );
}
