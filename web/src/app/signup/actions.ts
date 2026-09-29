"use server";

import { isAPIError } from "better-auth/api";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { authServer } from "@/lib/auth";

export type SignUpState = { error: string | null; username?: string; email?: string };

// Mirrors the username plugin's defaults (3-30 chars, letters, digits,
// underscores and dots) so most mistakes are caught before the round trip.
const USERNAME_PATTERN = /^[a-zA-Z0-9_.]{3,30}$/;

// Friendly copy for the Better Auth error codes a sign-up can hit.
const SIGN_UP_ERRORS: Partial<Record<string, string>> = {
  USERNAME_IS_ALREADY_TAKEN: "That username is taken. Try another one.",
  USER_ALREADY_EXISTS: "An account with that email already exists. Sign in instead.",
  USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL:
    "An account with that email already exists. Sign in instead.",
  INVALID_USERNAME: "Usernames can only contain letters, numbers, underscores and dots.",
  USERNAME_TOO_SHORT: "Use at least 3 characters for the username.",
  USERNAME_TOO_LONG: "Use at most 30 characters for the username.",
  INVALID_EMAIL: "Enter a valid email address.",
  PASSWORD_TOO_SHORT: "Use at least 8 characters for the password.",
  PASSWORD_TOO_LONG: "That password is too long.",
};

// useActionState action: validation problems come back as { error } for
// the form to show inline. Sign-up signs the user in (autoSignIn), and the
// redirect stays outside the try so Next's redirect throw propagates.
export async function signUp(_prev: SignUpState, formData: FormData): Promise<SignUpState> {
  const username = String(formData.get("username") ?? "").trim();
  const email = String(formData.get("email") ?? "")
    .toLowerCase()
    .trim();
  const password = String(formData.get("password") ?? "");
  if (!username) return { error: "Choose a username.", email };
  if (!USERNAME_PATTERN.test(username)) {
    return {
      error: "Usernames are 3 to 30 characters: letters, numbers, underscores and dots.",
      username,
      email,
    };
  }
  if (!email) return { error: "Enter your email address.", username };
  if (password.length < 8) {
    return { error: "Use at least 8 characters for the password.", username, email };
  }

  try {
    await authServer.api.signUpEmail({
      body: { email, password, name: username, username },
      headers: await headers(),
    });
  } catch (err) {
    if (isAPIError(err)) {
      return {
        error:
          SIGN_UP_ERRORS[err.body?.code ?? ""] ??
          "Could not create your account. Please try again.",
        username,
        email,
      };
    }
    throw err;
  }
  redirect("/dashboard");
}
