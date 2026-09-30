"use client";

import { AlertTriangle, Loader2 } from "lucide-react";
import { useState, useTransition } from "react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { MemberRow } from "@/lib/queries-members";

import { resetMemberPassword } from "./actions";
import { TemporaryPasswordField } from "./password-field";
import { SignInDetails } from "./sign-in-details";
import { generateTemporaryPassword, MIN_PASSWORD, validatePassword } from "./validation";

// Set a new temporary password, then show the sign-in details to pass on.
// Opened from the row menu (no trigger here), so Radix returns focus to
// the menu button when it closes.
export function ResetPasswordDialog({
  member,
  open,
  onOpenChange,
  onDone,
}: {
  member: MemberRow;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onDone?: () => void;
}) {
  const who = member.username ?? member.email;
  const [password, setPassword] = useState(generateTemporaryPassword);
  const [fieldError, setFieldError] = useState<string | undefined>();
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function change(next: boolean) {
    if (pending) return;
    onOpenChange(next);
    if (!next) {
      // Ready for the next time it opens.
      setPassword(generateTemporaryPassword());
      setFieldError(undefined);
      setError(null);
      setDone(null);
    }
  }

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const invalid = validatePassword(password);
    if (invalid) {
      setFieldError(invalid);
      return;
    }
    startTransition(async () => {
      const res = await resetMemberPassword(member.id, password);
      if (res.ok) {
        setDone(password);
        onDone?.();
        return;
      }
      if (res.fieldErrors?.password) setFieldError(res.fieldErrors.password);
      else setError(res.error);
    });
  }

  return (
    <Dialog open={open} onOpenChange={change}>
      <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto">
        {done ? (
          <div className="flex flex-col gap-4">
            <DialogHeader className="text-left">
              <DialogTitle>Password reset</DialogTitle>
              <DialogDescription>
                {who} is signed out everywhere. Send them these details yourself.
              </DialogDescription>
            </DialogHeader>
            <SignInDetails username={who} password={done} reset />
            <DialogFooter>
              <Button type="button" onClick={() => change(false)}>
                Done
              </Button>
            </DialogFooter>
          </div>
        ) : (
          <form onSubmit={submit} noValidate className="flex flex-col gap-4">
            <DialogHeader className="text-left">
              <DialogTitle>Reset password for {who}?</DialogTitle>
              <DialogDescription>
                This signs them out everywhere. Give them the temporary password below;
                they&rsquo;ll choose their own when they next sign in.
              </DialogDescription>
            </DialogHeader>
            <TemporaryPasswordField
              id="reset-password"
              value={password}
              onChange={(v) => {
                setPassword(v);
                setFieldError(undefined);
              }}
              error={fieldError}
            />
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
              <Button type="submit" disabled={pending || password.length < MIN_PASSWORD}>
                {pending && <Loader2 className="animate-spin" />}
                Reset password
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
