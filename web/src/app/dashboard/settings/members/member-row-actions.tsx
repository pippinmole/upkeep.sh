"use client";

import { MoreHorizontal } from "lucide-react";
import { useState } from "react";

import { ActionDialog } from "@/components/action-dialog";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { MemberRow } from "@/lib/queries-members";
import { ROLE_LABELS } from "@/lib/roles";

import { removeMember, resetMemberPassword, setMemberDisabled, setMemberRole } from "./actions";
import { TemporaryPasswordField } from "./password-field";
import { generateTemporaryPassword } from "./validation";

type Dialog = "role" | "reset" | "disable" | "remove" | null;

// Admin-only row menu. The server refuses changes to your own account and
// any change that would leave no enabled administrator; the menu isn't
// shown on your own row either.
export function MemberRowActions({ member }: { member: MemberRow }) {
  const [dialog, setDialog] = useState<Dialog>(null);
  const [password, setPassword] = useState("");
  const who = member.username ?? member.email;
  const nextRole = member.role === "admin" ? "member" : "admin";
  const close = (open: boolean) => !open && setDialog(null);

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon" className="size-8" aria-label={`Actions for ${who}`}>
            <MoreHorizontal className="size-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem onSelect={() => setDialog("role")}>
            Make {ROLE_LABELS[nextRole].toLowerCase()}
          </DropdownMenuItem>
          <DropdownMenuItem
            onSelect={() => {
              setPassword(generateTemporaryPassword());
              setDialog("reset");
            }}
          >
            Reset password…
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => setDialog("disable")}>
            {member.disabled ? "Enable" : "Disable"}
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem className="text-destructive" onSelect={() => setDialog("remove")}>
            Remove…
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <ActionDialog
        open={dialog === "role"}
        onOpenChange={close}
        title={`Make ${who} ${ROLE_LABELS[nextRole].toLowerCase()}?`}
        description={
          nextRole === "admin"
            ? "Administrators can change everything, including members and their roles."
            : "Members can see everything but can't change anything."
        }
        actionLabel={`Make ${ROLE_LABELS[nextRole].toLowerCase()}`}
        run={() => setMemberRole(member.id, nextRole)}
      />
      <ActionDialog
        open={dialog === "reset"}
        onOpenChange={close}
        title={`Reset ${who}'s password?`}
        description="They're signed out everywhere and must choose a new password when they next sign in with this one."
        actionLabel="Reset password"
        run={() => resetMemberPassword(member.id, password)}
      >
        <TemporaryPasswordField id="reset-password" value={password} onChange={setPassword} />
      </ActionDialog>
      <ActionDialog
        open={dialog === "disable"}
        onOpenChange={close}
        title={member.disabled ? `Enable ${who}?` : `Disable ${who}?`}
        description={
          member.disabled
            ? "They can sign in again with their current password."
            : "They're signed out everywhere and can't sign in until an administrator enables them again."
        }
        actionLabel={member.disabled ? "Enable" : "Disable"}
        destructive={!member.disabled}
        run={() => setMemberDisabled(member.id, !member.disabled)}
      />
      <ActionDialog
        open={dialog === "remove"}
        onOpenChange={close}
        title={`Remove ${who}?`}
        description="Their account is deleted and they can't sign in. Hosts, agents and everything else in the workspace stay."
        actionLabel="Remove"
        destructive
        confirmText={who}
        run={() => removeMember(member.id)}
      />
    </>
  );
}
