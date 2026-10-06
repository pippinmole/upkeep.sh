"use server";

import { isAPIError } from "better-auth/api";
import { revalidatePath } from "next/cache";

import { authServer } from "@/lib/auth";
import { pool } from "@/lib/db";
import { ForbiddenError, requireActionViewer, type Viewer } from "@/lib/viewer";

import { INTEGRATIONS_URL } from "./links";
import { revokeConsent, type RevokeResult } from "./revoke";
import { createToken, type CreateTokenResult, revokeToken } from "./tokens";

// Settings > Integrations server actions. Members and admins both get
// here; each action checks what the viewer may do itself (revoke.ts,
// tokens.ts), whatever the UI offers.

async function actionViewer(): Promise<Viewer | { ok: false; error: string }> {
  try {
    return await requireActionViewer();
  } catch (err) {
    if (err instanceof ForbiddenError) return { ok: false, error: err.message };
    throw err;
  }
}

// Connected apps: Revoke. revokeConsent loads the consent and lets a member
// revoke only their own.
export async function revokeConnectedApp(consentId: string): Promise<RevokeResult> {
  const viewer = await actionViewer();
  if (!("userId" in viewer)) return viewer;
  const client = await pool.connect();
  let res: RevokeResult;
  try {
    res = await revokeConsent(client, viewer, consentId);
  } finally {
    client.release();
  }
  if (res.ok) revalidatePath(INTEGRATIONS_URL, "layout");
  return res;
}

// API tokens: Create, for the viewer. The token comes back once, for the
// dialog to show; only its hash is stored.
export async function createApiToken(input: unknown): Promise<CreateTokenResult> {
  const viewer = await actionViewer();
  if (!("userId" in viewer)) return viewer;
  let res: CreateTokenResult;
  try {
    res = await createToken((body) => authServer.api.createApiKey({ body }), viewer, input);
  } catch (err) {
    if (isAPIError(err)) return { ok: false, error: err.message || "Couldn't create the token." };
    throw err;
  }
  if (res.ok) revalidatePath(INTEGRATIONS_URL, "layout");
  return res;
}

// API tokens: Revoke. Members revoke their own, admins anyone's.
export async function revokeApiToken(tokenId: string): Promise<RevokeResult> {
  const viewer = await actionViewer();
  if (!("userId" in viewer)) return viewer;
  const res = await revokeToken(pool, viewer, tokenId);
  if (res.ok) revalidatePath(INTEGRATIONS_URL, "layout");
  return res;
}
