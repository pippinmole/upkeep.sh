import type { Metadata } from "next";
import Link from "next/link";

import { AuthShell } from "./auth-shell";
import { LoginForm } from "./login-form";

export const metadata: Metadata = {
  title: "Sign in",
};

export default function LoginPage() {
  return (
    <AuthShell
      title="Sign in"
      description="Welcome back. Sign in to see your estate."
      footer={
        <p>
          New here?{" "}
          <Link href="/signup" className="text-foreground font-medium hover:underline">
            Create an account
          </Link>
        </p>
      }
    >
      <LoginForm />
    </AuthShell>
  );
}
