import type { Metadata } from "next";
import Link from "next/link";

import { installHasUsers } from "@/lib/auth";
import { oauthQueryFrom, type PageSearchParams } from "@/lib/oauth-query";

import { AuthShell } from "./auth-shell";
import { LoginForm } from "./login-form";

export const metadata: Metadata = {
  title: "Sign in",
};

export const dynamic = "force-dynamic";

// Sign-up is only offered while the install has no account yet (it creates
// the administrator); afterwards administrators create accounts.
//
// An MCP client's authorization request lands here (as signed query
// parameters) when the user isn't signed in; signing in continues it
// (lib/oauth-query.ts).
export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<PageSearchParams>;
}) {
  const [bootstrapping, oauthQuery] = await Promise.all([
    installHasUsers().then((has) => !has),
    searchParams.then(oauthQueryFrom),
  ]);
  return (
    <AuthShell
      title="Sign in"
      description={
        oauthQuery
          ? "Sign in to connect an app to upkeep.sh."
          : "Welcome back. Sign in to see your estate."
      }
      footer={
        bootstrapping ? (
          <p>
            New install?{" "}
            <Link href="/signup" className="text-foreground font-medium hover:underline">
              Create the first account
            </Link>
          </p>
        ) : (
          <p>No account? Ask an administrator to create one.</p>
        )
      }
    >
      <LoginForm oauthQuery={oauthQuery} />
    </AuthShell>
  );
}
