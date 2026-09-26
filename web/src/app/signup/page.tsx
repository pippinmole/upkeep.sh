import type { Metadata } from "next";

import { signUp } from "./actions";

export const metadata: Metadata = {
  title: "Sign up",
};

export default function SignupPage() {
  return (
    <main className="mx-auto flex min-h-screen max-w-sm flex-col justify-center gap-6 px-4">
      <h1 className="text-xl font-semibold">Create an account</h1>
      <form action={signUp} className="flex flex-col gap-3">
        <input
          name="email"
          type="email"
          placeholder="you@example.com"
          required
          className="rounded border px-3 py-2"
        />
        <input
          name="password"
          type="password"
          placeholder="Password (8+ characters)"
          required
          minLength={8}
          className="rounded border px-3 py-2"
        />
        <button type="submit" className="rounded bg-black px-3 py-2 text-white">
          Sign up
        </button>
      </form>
    </main>
  );
}
