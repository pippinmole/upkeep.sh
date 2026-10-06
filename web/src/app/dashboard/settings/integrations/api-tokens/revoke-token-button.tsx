"use client";

import { useState } from "react";

import { ActionDialog } from "@/components/action-dialog";
import { Button } from "@/components/ui/button";
import type { ApiTokenRow } from "@/lib/queries-integrations";

import { revokeApiToken } from "../actions";

// Revoke one API token, after a confirm. The page revalidates on success,
// so the row goes away.
export function RevokeTokenButton({ token, isOwn }: { token: ApiTokenRow; isOwn: boolean }) {
  const [open, setOpen] = useState(false);
  const who = token.username ?? token.email ?? "this user";

  return (
    <>
      <Button
        variant="outline"
        size="sm"
        aria-label={`Revoke ${token.name}${isOwn ? "" : ` (${who})`}`}
        onClick={() => setOpen(true)}
      >
        Revoke…
      </Button>
      <ActionDialog
        open={open}
        onOpenChange={setOpen}
        title={isOwn ? `Revoke ${token.name}?` : `Revoke ${token.name} for ${who}?`}
        description="Anything still using it gets an authentication error on its next call. This can't be undone: create a new token to connect it again."
        actionLabel="Revoke"
        destructive
        run={() => revokeApiToken(token.id)}
      />
    </>
  );
}
