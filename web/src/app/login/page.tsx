import type { Metadata } from "next";
import Link from "next/link";

import { installHasUsers } from "@/lib/auth";

import { AuthShell } from "./auth-shell";
import { LoginForm } from "./login-form";

export const metadata: Metadata = {
  title: "Sign in",
};

export const dynamic = "force-dynamic";

// Sign-up is only offered while the install has no account yet (it creates
// the administrator); afterwards administrators create accounts.
export default async function LoginPage() {
  const bootstrapping = !(await installHasUsers());
  return (
    <AuthShell
      title="Sign in"
      description="Welcome back. Sign in to see your estate."
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
      <LoginForm />
    </AuthShell>
  );
}
