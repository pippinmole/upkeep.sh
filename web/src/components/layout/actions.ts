"use server";

import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { authServer } from "@/lib/auth";

export async function logOut() {
  // nextCookies clears the session cookie on the response.
  await authServer.api.signOut({ headers: await headers() });
  redirect("/login");
}
