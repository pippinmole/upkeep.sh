"use client";

import { AlertTriangle, Loader2, UserPlus } from "lucide-react";
import { useState, useTransition } from "react";

import { FieldError } from "@/components/notifications/shared";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { Role } from "@/lib/roles";

import { createMember } from "./actions";
import { TemporaryPasswordField } from "./password-field";
import { RoleSelect } from "./role-select";
import { generateTemporaryPassword } from "./validation";

type Form = { username: string; email: string; name: string; role: Role; password: string };

const empty = (): Form => ({
  username: "",
  email: "",
  name: "",
  role: "member",
  password: generateTemporaryPassword(),
});

const TEXT_FIELDS = [
  { key: "username", label: "Username", hint: "Used to sign in.", autoComplete: "off" },
  { key: "email", label: "Email", hint: null, autoComplete: "off" },
  { key: "name", label: "Name (optional)", hint: null, autoComplete: "off" },
] as const;

export function AddMemberButton() {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<Form>(empty);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function change(next: boolean) {
    if (pending) return;
    setOpen(next);
    if (next) {
      setForm(empty());
      setErrors({});
      setError(null);
    }
  }

  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => ({ ...f, [k]: v }));

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    startTransition(async () => {
      const res = await createMember(form);
      if (res.ok) {
        setOpen(false);
        return;
      }
      setErrors(res.fieldErrors ?? {});
      setError(res.error);
    });
  }

  return (
    <>
      <Button onClick={() => change(true)}>
        <UserPlus />
        Add member
      </Button>
      <Dialog open={open} onOpenChange={change}>
        <DialogContent className="sm:max-w-lg">
          <form onSubmit={submit} className="flex flex-col gap-4">
            <DialogHeader>
              <DialogTitle>Add member</DialogTitle>
              <DialogDescription>
                Create an account with a temporary password, then share the username and password
                with them.
              </DialogDescription>
            </DialogHeader>
            {TEXT_FIELDS.map((f) => (
              <div key={f.key} className="flex flex-col gap-1.5">
                <Label htmlFor={`member-${f.key}`}>{f.label}</Label>
                <Input
                  id={`member-${f.key}`}
                  type={f.key === "email" ? "email" : "text"}
                  value={form[f.key]}
                  autoComplete={f.autoComplete}
                  autoCapitalize="none"
                  spellCheck={false}
                  required={f.key !== "name"}
                  aria-invalid={errors[f.key] ? true : undefined}
                  onChange={(e) => set(f.key, e.target.value)}
                />
                {f.hint && <p className="text-muted-foreground text-xs">{f.hint}</p>}
                <FieldError msg={errors[f.key]} />
              </div>
            ))}
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="member-role">Role</Label>
              <RoleSelect id="member-role" value={form.role} onChange={(r) => set("role", r)} />
              <FieldError msg={errors.role} />
            </div>
            <TemporaryPasswordField
              id="member-password"
              value={form.password}
              onChange={(v) => set("password", v)}
              error={errors.password}
            />
            {error && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => change(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={pending}>
                {pending && <Loader2 className="animate-spin" />}
                Add member
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}
