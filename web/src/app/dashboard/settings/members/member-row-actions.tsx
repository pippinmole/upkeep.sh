"use client";

import { MoreHorizontal } from "lucide-react";
import Link from "next/link";
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

import { type MemberActionResult, removeMember, setMemberDisabled, setMemberRole } from "./actions";
import { ResetPasswordDialog } from "./reset-password-dialog";

type Dialog = "role" | "reset" | "disable" | "remove" | null;

function MenuTrigger({ label }: { label: string }) {
  return (
    <DropdownMenuTrigger asChild>
      <Button variant="ghost" size="icon" className="size-8" aria-label={label}>
        <MoreHorizontal className="size-4" />
      </Button>
    </DropdownMenuTrigger>
  );
}

// Your own row: the server refuses changes to your own account here, so
// the only thing on offer is changing your password (as in the user menu).
export function OwnRowActions() {
  return (
    <DropdownMenu>
      <MenuTrigger label="Actions for your account" />
      <DropdownMenuContent align="end">
        <DropdownMenuItem asChild>
          <Link href="/change-password">Change your password</Link>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

// Admin-only row menu. The server refuses changes to your own account and
// any change that would leave no enabled administrator. onChanged runs
// after a change succeeds (the table highlights the row).
export function MemberRowActions({
  member,
  onChanged,
}: {
  member: MemberRow;
  onChanged?: (id: string) => void;
}) {
  const [dialog, setDialog] = useState<Dialog>(null);
  const who = member.username ?? member.email;
  const nextRole = member.role === "admin" ? "member" : "admin";
  const close = (open: boolean) => !open && setDialog(null);
  const changed = async (p: Promise<MemberActionResult>) => {
    const res = await p;
    if (res.ok) onChanged?.(member.id);
    return res;
  };

  return (
    <>
      <DropdownMenu>
        <MenuTrigger label={`Actions for ${who}`} />
        <DropdownMenuContent align="end">
          <DropdownMenuItem onSelect={() => setDialog("role")}>
            Make {ROLE_LABELS[nextRole].toLowerCase()}…
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => setDialog("reset")}>Reset password…</DropdownMenuItem>
          <DropdownMenuItem onSelect={() => setDialog("disable")}>
            {member.disabled ? "Enable…" : "Disable…"}
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem variant="destructive" onSelect={() => setDialog("remove")}>
            Remove member…
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <ActionDialog
        open={dialog === "role"}
        onOpenChange={close}
        title={`Make ${who} ${nextRole === "admin" ? "an administrator" : "a member"}?`}
        description={
          nextRole === "admin"
            ? "They'll be able to change everything, including members and their roles."
            : "They'll keep read-only access to everything but won't be able to change anything, including members."
        }
        actionLabel={`Make ${ROLE_LABELS[nextRole].toLowerCase()}`}
        run={() => changed(setMemberRole(member.id, nextRole))}
      />
      <ResetPasswordDialog
        member={member}
        open={dialog === "reset"}
        onOpenChange={close}
        onDone={() => onChanged?.(member.id)}
      />
      <ActionDialog
        open={dialog === "disable"}
        onOpenChange={close}
        title={member.disabled ? `Enable ${who}?` : `Disable ${who}?`}
        description={
          member.disabled
            ? "They can sign in again with their current password."
            : "They're signed out everywhere and can't sign in until an administrator enables them again."
        }
        actionLabel={member.disabled ? "Enable account" : "Disable account"}
        destructive={!member.disabled}
        run={() => changed(setMemberDisabled(member.id, !member.disabled))}
      />
      <ActionDialog
        open={dialog === "remove"}
        onOpenChange={close}
        title={`Remove ${who}?`}
        description="Their account and password are deleted. Hosts, agents and everything else in the workspace stay. To block sign-in without deleting the account, disable it instead."
        actionLabel="Remove member"
        destructive
        confirmText={who}
        run={() => removeMember(member.id)}
      />
    </>
  );
}
