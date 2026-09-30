// Roles (docs/MEMBERS.md). Client-safe: no server imports.
//
// admin  - full access: every write in the dashboard, plus Members.
// member - read-only: sees everything in the workspace, changes nothing
//          (except their own password).
//
// The server enforces this (lib/viewer.ts requireAdmin, called by every
// mutating server action); the client only uses it to hide or disable
// controls.

export const ROLES = ["admin", "member"] as const;
export type Role = (typeof ROLES)[number];

export const ROLE_LABELS: Record<Role, string> = {
  admin: "Administrator",
  member: "Member",
};

export const ROLE_DESCRIPTIONS: Record<Role, string> = {
  admin: "Full access: hosts, agents, channels, alerts, reports and members.",
  member: "Read-only: sees everything, changes nothing.",
};

export function isRole(v: unknown): v is Role {
  return typeof v === "string" && (ROLES as readonly string[]).includes(v);
}

// Shown when a member reaches a write they can't make (server-side refusal).
export const ADMIN_ONLY_MESSAGE = "Only administrators can make changes.";
