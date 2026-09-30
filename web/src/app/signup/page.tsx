import type { Metadata } from "next";
import Link from "next/link";

import { Button } from "@/components/ui/button";
import { installHasUsers } from "@/lib/auth";

import { AuthShell } from "../login/auth-shell";
import { SignupForm } from "./signup-form";

export const metadata: Metadata = {
  title: "Sign up",
};

// Read the users table on every request: the page flips to "closed" as soon
// as the first account exists.
export const dynamic = "force-dynamic";

const signInLink = (
  <p>
    Already have an account?{" "}
    <Link href="/login" className="text-foreground font-medium hover:underline">
      Sign in
    </Link>
  </p>
);

// Sign-up only bootstraps the install's first account, which becomes its
// administrator (docs/MEMBERS.md). After that, accounts are created by an
// administrator under Settings > Members; the server refuses sign-ups too
// (lib/auth.ts), this page only explains it.
export default async function SignupPage() {
  if (await installHasUsers()) {
    return (
      <AuthShell
        title="Sign-up is closed"
        description="This install already has an administrator. Ask them to create an account for you."
        footer={signInLink}
      >
        <Button asChild className="w-full">
          <Link href="/login">Go to sign in</Link>
        </Button>
      </AuthShell>
    );
  }
  return (
    <AuthShell
      title="Set up upkeep.sh"
      description="Create the first account. It becomes the administrator, who adds everyone else."
      footer={signInLink}
    >
      <SignupForm />
    </AuthShell>
  );
}
