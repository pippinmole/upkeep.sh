import type { QueryResultRow } from "pg";

import { isUuid } from "@/lib/queries-inventory";
import type { Viewer } from "@/lib/viewer";

// Revoking a connected app (actions.ts), apart from the server action so
// the permission rules can be tested against a fake database client.
//
// One transaction: the consent and that user's access and refresh tokens
// for the client go together. The consent alone isn't enough: /api/mcp
// checks it on every call (getMcpViewer), but the token endpoint would
// still exchange the refresh token for a new access token. The client row
// stays: a CIMD client (Claude Code) is shared by every user who connects it.

export const REVOKE_ERRORS = {
  notFound: "That app is no longer connected. Reload the page.",
  forbidden: "You can only revoke your own connected apps.",
};

export type RevokeResult = { ok: true } | { ok: false; error: string };

// What revokeConsent needs of a pg PoolClient (one connection, so the
// transaction holds).
export type Db = {
  query<R extends QueryResultRow = QueryResultRow>(
    text: string,
    values?: unknown[],
  ): Promise<{ rows: R[] }>;
};

export async function revokeConsent(
  db: Db,
  viewer: Pick<Viewer, "userId" | "isAdmin">,
  consentId: unknown,
): Promise<RevokeResult> {
  if (typeof consentId !== "string" || !isUuid(consentId)) {
    return { ok: false, error: REVOKE_ERRORS.notFound };
  }
  await db.query("BEGIN");
  try {
    const { rows } = await db.query<{ client_id: string; user_id: string | null }>(
      `SELECT client_id, user_id FROM oauth_consents WHERE id = $1 FOR UPDATE`,
      [consentId],
    );
    const consent = rows[0];
    if (!consent || (!viewer.isAdmin && consent.user_id !== viewer.userId)) {
      await db.query("ROLLBACK");
      return { ok: false, error: consent ? REVOKE_ERRORS.forbidden : REVOKE_ERRORS.notFound };
    }
    const params = [consent.client_id, consent.user_id];
    // Access tokens first: they reference refresh tokens (refresh_id).
    await db.query(
      `DELETE FROM oauth_access_tokens WHERE client_id = $1 AND user_id IS NOT DISTINCT FROM $2`,
      params,
    );
    await db.query(
      `DELETE FROM oauth_refresh_tokens WHERE client_id = $1 AND user_id IS NOT DISTINCT FROM $2`,
      params,
    );
    await db.query(`DELETE FROM oauth_consents WHERE id = $1`, [consentId]);
    await db.query("COMMIT");
    return { ok: true };
  } catch (err) {
    await db.query("ROLLBACK").catch(() => {});
    throw err;
  }
}
