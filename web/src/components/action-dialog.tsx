"use client";

import { AlertTriangle, Loader2 } from "lucide-react";
import { type ReactNode, useState, useTransition } from "react";

import type { ActionResult } from "@/app/dashboard/manage-actions";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

// A confirm dialog for a management server action. It stays open while
// the action runs and shows the action's error, closing only on success.
// With confirmText, the user must type it before the action is enabled
// (typed confirmation for destructive actions); the typed value is passed
// to run() so the server can check it too.
export function ActionDialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  actionLabel,
  destructive,
  confirmText,
  run,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: ReactNode;
  children?: ReactNode;
  actionLabel: string;
  destructive?: boolean;
  confirmText?: string;
  run: (typed: string) => Promise<ActionResult>;
}) {
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function change(next: boolean) {
    if (pending) return;
    onOpenChange(next);
    if (!next) {
      setTyped("");
      setError(null);
    }
  }

  function confirm() {
    setError(null);
    startTransition(async () => {
      const res = await run(typed);
      if (res.ok) change(false);
      else setError(res.error);
    });
  }

  const blocked = confirmText !== undefined && typed !== confirmText;

  return (
    <AlertDialog open={open} onOpenChange={change}>
      <AlertDialogContent
        // With a typed confirmation, start in its field rather than on Cancel.
        onOpenAutoFocus={(e) => {
          if (confirmText === undefined) return;
          e.preventDefault();
          document.getElementById("action-confirm")?.focus();
        }}
      >
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="flex flex-col gap-2">{description}</div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        {children}
        {confirmText !== undefined && (
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="action-confirm">
              Type <span className="font-mono font-semibold">{confirmText}</span> to confirm
            </Label>
            <Input
              id="action-confirm"
              value={typed}
              autoComplete="off"
              onChange={(e) => setTyped(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !blocked && !pending) confirm();
              }}
            />
          </div>
        )}
        {error && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel disabled={pending}>Cancel</AlertDialogCancel>
          <Button
            variant={destructive ? "destructive" : "default"}
            disabled={pending || blocked}
            onClick={confirm}
          >
            {pending && <Loader2 className="animate-spin" />}
            {actionLabel}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
