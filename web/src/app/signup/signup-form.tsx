"use client";

import { Loader2 } from "lucide-react";
import { useActionState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

import { signUp, type SignUpState } from "./actions";

const initial: SignUpState = { error: null };

export function SignupForm() {
  const [state, action, pending] = useActionState(signUp, initial);
  return (
    <form action={action} className="flex flex-col gap-4">
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="username">Username</Label>
        <Input
          id="username"
          name="username"
          type="text"
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          minLength={3}
          maxLength={30}
          pattern="[a-zA-Z0-9_.]+"
          defaultValue={state.username}
          required
          aria-describedby="username-help"
        />
        <p id="username-help" className="text-muted-foreground text-xs">
          3 to 30 characters: letters, numbers, underscores and dots
        </p>
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="email">Email</Label>
        <Input
          id="email"
          name="email"
          type="email"
          autoComplete="email"
          placeholder="you@example.com"
          defaultValue={state.email}
          required
        />
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="password">Password</Label>
        <Input
          id="password"
          name="password"
          type="password"
          autoComplete="new-password"
          minLength={8}
          required
          aria-describedby="password-help"
        />
        <p id="password-help" className="text-muted-foreground text-xs">
          At least 8 characters
        </p>
      </div>
      {state.error && (
        <p role="alert" className="text-destructive text-sm">
          {state.error}
        </p>
      )}
      <Button type="submit" disabled={pending}>
        {pending && <Loader2 className="animate-spin" />}
        Create account
      </Button>
    </form>
  );
}
