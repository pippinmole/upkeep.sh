import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { LogOutButton } from "@/components/layout/log-out-button";
import { safeReturnPath } from "@/lib/oauth-query";
import { getViewer } from "@/lib/viewer";

import { AuthShell } from "../login/auth-shell";
import { ChangePasswordForm } from "./change-password-form";

export const metadata: Metadata = { title: "Change password" };

// Outside /dashboard on purpose: the dashboard layout sends a user with a
// temporary password here, so this page can't sit behind that check.
// `next`: the OAuth consent page to return to, when an MCP sign-in sent a
// user with a temporary password here first.
export default async function ChangePasswordPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string | string[] }>;
}) {
  const viewer = await getViewer();
  if (!viewer) redirect("/login");
  const temporary = viewer.mustChangePassword;
  const { next: nextParam } = await searchParams;
  const next = safeReturnPath(typeof nextParam === "string" ? nextParam : null);
  return (
    <AuthShell
      title={temporary ? "Choose a new password" : "Change password"}
      description={
        temporary
          ? "An administrator set a temporary password for this account. Pick your own to continue."
          : `Signed in as ${viewer.username ?? viewer.email}. Other sessions are signed out.`
      }
      footer={
        temporary ? (
          <LogOutButton />
        ) : (
          <Link href="/dashboard" className="text-foreground font-medium hover:underline">
            Back to the dashboard
          </Link>
        )
      }
    >
      <ChangePasswordForm temporary={temporary} next={next} />
    </AuthShell>
  );
}
