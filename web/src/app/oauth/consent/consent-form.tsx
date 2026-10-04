"use client";

import { Loader2 } from "lucide-react";
import { useActionState } from "react";

import { Button } from "@/components/ui/button";

import { type ConsentState, decideConsent } from "./actions";

const initial: ConsentState = { error: null };

export function ConsentForm({ oauthQuery }: { oauthQuery: string }) {
  const [state, action, pending] = useActionState(decideConsent, initial);
  return (
    <form action={action} className="flex flex-col gap-3">
      <input type="hidden" name="oauth_query" value={oauthQuery} />
      {state.error && (
        <p role="alert" className="text-destructive text-sm">
          {state.error}
        </p>
      )}
      <div className="flex gap-2">
        <Button
          type="submit"
          name="decision"
          value="deny"
          variant="outline"
          className="flex-1"
          disabled={pending}
        >
          Deny
        </Button>
        <Button type="submit" name="decision" value="allow" className="flex-1" disabled={pending}>
          {pending && <Loader2 className="animate-spin" />}
          Allow
        </Button>
      </div>
    </form>
  );
}
