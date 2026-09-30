import { Ban } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import type { MemberRow } from "@/lib/queries-members";

export type MemberStatus = "active" | "pending" | "disabled";

export const memberStatus = (m: MemberRow): MemberStatus =>
  m.disabled ? "disabled" : m.mustChangePassword ? "pending" : "active";

export const STATUS_OPTIONS: { value: MemberStatus; label: string }[] = [
  { value: "active", label: "Active" },
  { value: "pending", label: "Needs new password" },
  { value: "disabled", label: "Disabled" },
];

// One line at every width; Disabled carries an icon as well as its colour.
export function MemberStatusBadge({ status }: { status: MemberStatus }) {
  if (status === "disabled") {
    return (
      <Badge variant="neutral" className="whitespace-nowrap">
        <Ban />
        Disabled
      </Badge>
    );
  }
  if (status === "pending") {
    return (
      <Badge
        variant="warning"
        className="whitespace-nowrap"
        title="Signed in with a temporary password, or hasn't signed in yet. They'll choose their own password at next sign-in."
      >
        Needs new password
      </Badge>
    );
  }
  return (
    <Badge variant="success" className="whitespace-nowrap">
      Active
    </Badge>
  );
}
