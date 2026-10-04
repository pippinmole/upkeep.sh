"use server";

import { revalidatePath } from "next/cache";

import { pool } from "@/lib/db";
import { ForbiddenError, requireActionViewer } from "@/lib/viewer";

import { INTEGRATIONS_URL } from "./links";
import { revokeConsent, type RevokeResult } from "./revoke";

// Settings > Integrations > Connected apps: Revoke. Members and admins both
// get here; revokeConsent loads the consent and lets a member revoke only
// their own.
export async function revokeConnectedApp(consentId: string): Promise<RevokeResult> {
  let viewer;
  try {
    viewer = await requireActionViewer();
  } catch (err) {
    if (err instanceof ForbiddenError) return { ok: false, error: err.message };
    throw err;
  }
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
