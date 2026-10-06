"use client";

import { useState } from "react";

import { ActionDialog } from "@/components/action-dialog";
import { Button } from "@/components/ui/button";
import type { ConnectedAppRow } from "@/lib/queries-integrations";

import { revokeConnectedApp } from "../actions";

// Revoke one connected app, after a confirm. The page revalidates on
// success, so the row goes away.
export function RevokeAppButton({ app, isOwn }: { app: ConnectedAppRow; isOwn: boolean }) {
  const [open, setOpen] = useState(false);
  const who = app.username ?? app.email ?? "this user";

  return (
    <>
      <Button
        variant="outline"
        size="sm"
        aria-label={`Revoke ${app.clientName}${isOwn ? "" : ` for ${who}`}`}
        onClick={() => setOpen(true)}
      >
        Revoke…
      </Button>
      <ActionDialog
        open={open}
        onOpenChange={setOpen}
        title={isOwn ? `Revoke ${app.clientName}?` : `Revoke ${app.clientName} for ${who}?`}
        description={
          isOwn
            ? `${app.clientName} is signed out: its next call fails, and it can only read the workspace again after you sign in and allow it again.`
            : `${app.clientName} is signed out for ${who}: its next call fails, and it can only read the workspace again after they sign in and allow it again.`
        }
        actionLabel="Revoke"
        destructive
        run={() => revokeConnectedApp(app.id)}
      />
    </>
  );
}
