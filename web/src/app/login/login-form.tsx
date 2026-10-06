"use client";

import { Loader2 } from "lucide-react";
import { useActionState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

import { type SignInState, signInWithPassword } from "./actions";

const initial: SignInState = { error: null };

// oauthQuery: the signed authorization request this sign-in continues, if
// an MCP client sent the user here.
export function LoginForm({ oauthQuery }: { oauthQuery?: string | null }) {
  const [state, action, pending] = useActionState(signInWithPassword, initial);
  return (
    <form action={action} className="flex flex-col gap-4">
      {oauthQuery && <input type="hidden" name="oauth_query" value={oauthQuery} />}
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="username">Username</Label>
        <Input
          id="username"
          name="username"
          type="text"
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          defaultValue={state.username}
          required
        />
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="password">Password</Label>
        <Input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
          aria-invalid={state.error ? true : undefined}
          aria-describedby={state.error ? "login-error" : undefined}
        />
      </div>
      {state.error && (
        <p id="login-error" role="alert" className="text-destructive text-sm">
          {state.error}
        </p>
      )}
      <Button type="submit" disabled={pending}>
        {pending && <Loader2 className="animate-spin" />}
        Sign in
      </Button>
    </form>
  );
}
