import { isUuid } from "@/lib/queries-inventory";
import type { Viewer } from "@/lib/viewer";

import type { Db, RevokeResult } from "./revoke";
import { expiresInSeconds, newTokenSchema } from "./token-options";

// Creating and revoking API tokens (actions.ts), apart from the server
// actions so the permission rules can be tested without Next.js or a
// database:
//   - anyone signed in (members and admins) creates tokens, always for
//     themselves: the owner is the viewer, never something the form sends;
//   - members revoke their own tokens, admins anyone's.
// Revoking deletes the row ourselves rather than through the plugin's
// delete endpoint, which only lets a token's owner delete it. Tokens are
// stored in the database only (no secondary storage), so the row is all
// there is: the next call with the token gets a 401.

export const TOKEN_ERRORS = {
  notFound: "That token no longer exists. Reload the page.",
  forbidden: "You can only revoke your own API tokens.",
};

// The plugin's create call (authServer.api.createApiKey), as a server call:
// no request headers, so the owner is the userId given.
export type CreateKey = (body: {
  name: string;
  expiresIn: number | null;
  userId: string;
}) => Promise<{ key: string; expiresAt: Date | string | null }>;

export type CreateTokenResult =
  | { ok: true; token: string; name: string; expiresAt: string | null }
  | { ok: false; error: string; fieldErrors?: Record<string, string> };

export async function createToken(
  createKey: CreateKey,
  viewer: Pick<Viewer, "userId">,
  input: unknown,
): Promise<CreateTokenResult> {
  const parsed = newTokenSchema.safeParse(input);
  if (!parsed.success) {
    const fieldErrors: Record<string, string> = {};
    for (const issue of parsed.error.issues) {
      const key = String(issue.path[0] ?? "");
      if (key && !fieldErrors[key]) fieldErrors[key] = issue.message;
    }
    return { ok: false, error: "Check the highlighted fields.", fieldErrors };
  }
  const { name, expiry } = parsed.data;
  const created = await createKey({
    name,
    expiresIn: expiresInSeconds(expiry),
    userId: viewer.userId,
  });
  return {
    ok: true,
    token: created.key,
    name,
    expiresAt: created.expiresAt ? new Date(created.expiresAt).toISOString() : null,
  };
}

// One statement, so the ownership check and the delete can't be split by
// a concurrent change. When nothing was deleted, a second look tells "not
// yours" from "gone".
export async function revokeToken(
  db: Db,
  viewer: Pick<Viewer, "userId" | "isAdmin">,
  tokenId: unknown,
): Promise<RevokeResult> {
  if (typeof tokenId !== "string" || !isUuid(tokenId)) {
    return { ok: false, error: TOKEN_ERRORS.notFound };
  }
  const { rows } = await db.query<{ id: string }>(
    `DELETE FROM api_tokens WHERE id = $1 AND ($2::uuid IS NULL OR user_id = $2) RETURNING id`,
    [tokenId, viewer.isAdmin ? null : viewer.userId],
  );
  if (rows.length > 0) return { ok: true };
  const { rows: exists } = await db.query(`SELECT 1 FROM api_tokens WHERE id = $1`, [tokenId]);
  return { ok: false, error: exists.length > 0 ? TOKEN_ERRORS.forbidden : TOKEN_ERRORS.notFound };
}
