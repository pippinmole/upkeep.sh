"use server";

import { AuthError } from "next-auth";

import { signIn } from "@/lib/auth";

export type SignInState = { error: string | null; email?: string };

// useActionState action. Bad credentials come back as { error }; any other
// throw, including the redirect signIn throws on success, propagates.
export async function signInWithPassword(
  _prev: SignInState,
  formData: FormData,
): Promise<SignInState> {
  const email = String(formData.get("email") ?? "").trim();
  try {
    await signIn("credentials", {
      email,
      password: formData.get("password"),
      redirectTo: "/dashboard",
    });
  } catch (err) {
    if (err instanceof AuthError) {
      return {
        error:
          err.type === "CredentialsSignin"
            ? "Wrong email or password."
            : "Could not sign in. Please try again.",
        email,
      };
    }
    throw err;
  }
  return { error: null };
}
