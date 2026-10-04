"use client";

import { Loader2 } from "lucide-react";
import { useActionState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

import { changePassword, type ChangePasswordState } from "./actions";

const initial: ChangePasswordState = { error: null };

const FIELDS = [
  { name: "currentPassword", label: "Current password", autoComplete: "current-password" },
  { name: "newPassword", label: "New password", autoComplete: "new-password" },
  { name: "confirmPassword", label: "Confirm new password", autoComplete: "new-password" },
] as const;

export function ChangePasswordForm({
  temporary,
  next,
}: {
  temporary: boolean;
  next?: string | null;
}) {
  const [state, action, pending] = useActionState(changePassword, initial);
  return (
    <form action={action} className="flex flex-col gap-4">
      {next && <input type="hidden" name="next" value={next} />}
      {FIELDS.map((f) => (
        <div key={f.name} className="flex flex-col gap-1.5">
          <Label htmlFor={f.name}>
            {f.name === "currentPassword" && temporary ? "Temporary password" : f.label}
          </Label>
          <Input
            id={f.name}
            name={f.name}
            type="password"
            autoComplete={f.autoComplete}
            minLength={f.name === "currentPassword" ? undefined : 8}
            required
            aria-invalid={state.error ? true : undefined}
            aria-describedby={state.error ? "change-password-error" : undefined}
          />
        </div>
      ))}
      {state.error && (
        <p id="change-password-error" role="alert" className="text-destructive text-sm">
          {state.error}
        </p>
      )}
      <Button type="submit" disabled={pending}>
        {pending && <Loader2 className="animate-spin" />}
        Change password
      </Button>
    </form>
  );
}
