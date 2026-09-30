"use client";

import { AlertTriangle, Loader2, Plus } from "lucide-react";
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

import { createMember } from "./actions";
import { AddMemberFields, fieldInputId, type NewMemberForm } from "./add-member-fields";
import { SignInDetails } from "./sign-in-details";
import { firstInvalidField, generateTemporaryPassword, validateNewMember } from "./validation";

const empty = (): NewMemberForm => ({
  username: "",
  email: "",
  name: "",
  role: "member",
  password: generateTemporaryPassword(),
});

type Created = { username: string; password: string };

function focusField(fieldErrors: Record<string, string>) {
  const key = firstInvalidField(fieldErrors);
  if (key) document.getElementById(fieldInputId(key))?.focus();
}

// Two steps: the form, then the sign-in details to pass on (shown once).
// The same checks run here, before the round trip, and on the server.
export function AddMemberButton() {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<NewMemberForm>(empty);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<Created | null>(null);
  const [again, setAgain] = useState(false);
  const [pending, startTransition] = useTransition();

  function reset(addingAnother: boolean) {
    setForm(empty());
    setErrors({});
    setError(null);
    setCreated(null);
    setAgain(addingAnother);
  }

  function change(next: boolean) {
    if (pending) return;
    setOpen(next);
    if (next) reset(false);
  }

  function set<K extends keyof NewMemberForm>(key: K, value: NewMemberForm[K]) {
    setForm((f) => ({ ...f, [key]: value }));
    if (errors[key]) {
      setErrors((prev) => {
        const next = { ...prev };
        delete next[key];
        return next;
      });
    }
  }

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const { member, fieldErrors } = validateNewMember(form);
    if (!member) {
      setErrors(fieldErrors);
      focusField(fieldErrors);
      return;
    }
    startTransition(async () => {
      const res = await createMember(form);
      if (res.ok) {
        setCreated({ username: member.username, password: member.password });
        return;
      }
      const serverFieldErrors = res.fieldErrors ?? {};
      setErrors(serverFieldErrors);
      // A field's problem shows on the field; the banner is for the rest.
      if (Object.keys(serverFieldErrors).length > 0) focusField(serverFieldErrors);
      else setError(res.error);
    });
  }

  return (
    <>
      <Button onClick={() => change(true)}>
        <Plus />
        Add member
      </Button>
      <Dialog open={open} onOpenChange={change}>
        <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-lg">
          {created ? (
            <div className="flex flex-col gap-4">
              <DialogHeader className="text-left">
                <DialogTitle>Member added</DialogTitle>
                <DialogDescription>
                  {created.username} can sign in now. Send them these details yourself.
                </DialogDescription>
              </DialogHeader>
              <SignInDetails username={created.username} password={created.password} />
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => reset(true)}>
                  Add another
                </Button>
                <Button type="button" onClick={() => change(false)}>
                  Done
                </Button>
              </DialogFooter>
            </div>
          ) : (
            <form onSubmit={submit} noValidate className="flex flex-col gap-4">
              <DialogHeader className="text-left">
                <DialogTitle>Add member</DialogTitle>
                <DialogDescription>
                  Sign-up is closed, so accounts are created here. No email is sent: you&rsquo;ll
                  share the sign-in details yourself.
                </DialogDescription>
              </DialogHeader>
              <AddMemberFields form={form} errors={errors} onChange={set} autoFocus={again} />
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
                  {pending ? "Adding…" : "Add member"}
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}
