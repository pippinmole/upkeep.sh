"use client";

import { AlertTriangle, Loader2, Plus } from "lucide-react";
import { useState, useTransition } from "react";

import { CopyButton } from "@/components/copy-button";
import { FieldError } from "@/components/notifications/shared";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
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
import { formatDate } from "@/lib/time";

import { createApiToken } from "../actions";
import {
  DEFAULT_TOKEN_EXPIRY,
  TOKEN_EXPIRIES,
  TOKEN_NAME_MAX,
  type TokenExpiry,
  newTokenSchema,
} from "../token-options";

type Created = { token: string; name: string; expiresAt: string | null };

// A read-only field with a copy button, for the one-time reveal.
function CopyField({ id, label, value }: { id: string; label: string; value: string }) {
  return (
    <div className="flex flex-col gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      <div className="relative">
        <Input
          id={id}
          readOnly
          value={value}
          className="pr-10 font-mono text-xs"
          onFocus={(e) => e.currentTarget.select()}
        />
        <CopyButton
          variant="ghost"
          className="absolute top-1/2 right-1 size-7 -translate-y-1/2"
          text={value}
        />
      </div>
    </div>
  );
}

// Two steps: the form (name, expiry), then the token, shown once: only its
// hash is stored. The same checks run here and in the server action.
export function CreateTokenButton({ mcpUrl }: { mcpUrl: string }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [expiry, setExpiry] = useState<TokenExpiry>(DEFAULT_TOKEN_EXPIRY);
  const [nameError, setNameError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<Created | null>(null);
  const [pending, startTransition] = useTransition();

  function change(next: boolean) {
    if (pending) return;
    setOpen(next);
    if (next) {
      setName("");
      setExpiry(DEFAULT_TOKEN_EXPIRY);
      setNameError(null);
      setError(null);
      setCreated(null);
    }
  }

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const parsed = newTokenSchema.safeParse({ name, expiry });
    if (!parsed.success) {
      setNameError(parsed.error.issues.find((i) => i.path[0] === "name")?.message ?? null);
      document.getElementById("token-name")?.focus();
      return;
    }
    startTransition(async () => {
      const res = await createApiToken(parsed.data);
      if (res.ok) {
        setCreated({ token: res.token, name: res.name, expiresAt: res.expiresAt });
        return;
      }
      if (res.fieldErrors?.name) setNameError(res.fieldErrors.name);
      else setError(res.error);
    });
  }

  return (
    <>
      <Button onClick={() => change(true)}>
        <Plus />
        Create token
      </Button>
      <Dialog open={open} onOpenChange={change}>
        <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-lg">
          {created ? (
            <div className="flex flex-col gap-4">
              <DialogHeader className="text-left">
                <DialogTitle>Token created</DialogTitle>
                <DialogDescription>
                  {created.name}{" "}
                  {created.expiresAt
                    ? `works until ${formatDate(created.expiresAt)}.`
                    : "works until you revoke it."}
                </DialogDescription>
              </DialogHeader>
              <Alert className="border-warning/40 bg-warning/10 text-warning-fg [&>svg]:text-warning-fg">
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>Copy the token now</AlertTitle>
                <AlertDescription>
                  It isn&rsquo;t shown again. If it&rsquo;s lost, revoke it and create a new one.
                </AlertDescription>
              </Alert>
              <CopyField id="token-value" label="Token" value={created.token} />
              <CopyField
                id="token-command"
                label="Add it to Claude Code"
                value={`claude mcp add --transport http upkeep ${mcpUrl} --header "Authorization: Bearer ${created.token}"`}
              />
              <DialogFooter>
                <Button type="button" onClick={() => change(false)} autoFocus>
                  Done
                </Button>
              </DialogFooter>
            </div>
          ) : (
            <form onSubmit={submit} noValidate className="flex flex-col gap-4">
              <DialogHeader className="text-left">
                <DialogTitle>Create API token</DialogTitle>
                <DialogDescription>
                  For an agent without a browser. It reads the workspace with your permissions.
                </DialogDescription>
              </DialogHeader>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="token-name">Name</Label>
                <Input
                  id="token-name"
                  value={name}
                  maxLength={TOKEN_NAME_MAX}
                  placeholder="nightly-triage"
                  autoComplete="off"
                  aria-invalid={nameError ? true : undefined}
                  aria-describedby={nameError ? "token-name-error" : undefined}
                  onChange={(e) => {
                    setName(e.target.value);
                    setNameError(null);
                  }}
                />
                <FieldError id="token-name-error" msg={nameError ?? undefined} />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="token-expiry">Expires after</Label>
                <Select value={expiry} onValueChange={(v) => setExpiry(v as TokenExpiry)}>
                  <SelectTrigger id="token-expiry" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {TOKEN_EXPIRIES.map((e) => (
                      <SelectItem key={e.value} value={e.value}>
                        {e.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {expiry === "never" && (
                  <p className="text-muted-foreground text-xs">
                    It works until it&rsquo;s revoked. Check its last use now and then.
                  </p>
                )}
              </div>
              {error && (
                <Alert variant="destructive">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}
              <DialogFooter>
                <Button
                  type="button"
                  variant="outline"
                  disabled={pending}
                  onClick={() => change(false)}
                >
                  Cancel
                </Button>
                <Button type="submit" disabled={pending}>
                  {pending && <Loader2 className="animate-spin" />}
                  {pending ? "Creating…" : "Create token"}
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}
