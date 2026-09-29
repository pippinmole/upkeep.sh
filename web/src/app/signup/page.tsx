import type { Metadata } from "next";
import Link from "next/link";

import { AuthShell } from "../login/auth-shell";
import { SignupForm } from "./signup-form";

export const metadata: Metadata = {
  title: "Sign up",
};

export default function SignupPage() {
  return (
    <AuthShell
      title="Create an account"
      description="Start monitoring your servers in a couple of minutes."
      footer={
        <p>
          Already have an account?{" "}
          <Link href="/login" className="text-foreground font-medium hover:underline">
            Sign in
          </Link>
        </p>
      }
    >
      <SignupForm />
    </AuthShell>
  );
}
