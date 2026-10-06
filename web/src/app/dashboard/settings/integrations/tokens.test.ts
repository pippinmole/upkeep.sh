/// <reference types="bun" />

import { beforeEach, describe, expect, test } from "bun:test";

import { type CreateKey, createToken, revokeToken, TOKEN_ERRORS } from "./tokens";

// createToken and revokeToken against fakes: the plugin's create call
// records what it was asked for, and the database fake applies the real
// SQL's conditions to an in-memory api_tokens.

const ADMIN = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const MEMBER = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const OTHER = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

const MEMBER_TOKEN = "11111111-1111-4111-8111-111111111111";
const OTHER_TOKEN = "22222222-2222-4222-8222-222222222222";
const UNKNOWN = "99999999-9999-4999-8999-999999999999";

const member = { userId: MEMBER, isAdmin: false };
const admin = { userId: ADMIN, isAdmin: true };

describe("createToken", () => {
  let calls: Parameters<CreateKey>[0][];
  const createKey: CreateKey = async (body) => {
    calls.push(body);
    return {
      key: "upk_secret",
      expiresAt: body.expiresIn ? new Date(Date.UTC(2027, 0, 1)) : null,
    };
  };

  beforeEach(() => {
    calls = [];
  });

  test("creates the token for the viewer, whatever the input says", async () => {
    const res = await createToken(createKey, member, {
      name: "  nightly  ",
      expiry: "90",
      userId: OTHER,
    });
    expect(res).toEqual({
      ok: true,
      token: "upk_secret",
      name: "nightly",
      expiresAt: "2027-01-01T00:00:00.000Z",
    });
    expect(calls).toEqual([{ name: "nightly", expiresIn: 90 * 86_400, userId: MEMBER }]);
  });

  test("an admin's token is the admin's own too", async () => {
    await createToken(createKey, admin, { name: "ci", expiry: "30", userId: MEMBER });
    expect(calls[0].userId).toBe(ADMIN);
  });

  test("each expiry choice, and never", async () => {
    for (const expiry of ["30", "90", "365", "never"]) {
      await createToken(createKey, member, { name: "t", expiry });
    }
    expect(calls.map((c) => c.expiresIn)).toEqual([30 * 86_400, 90 * 86_400, 365 * 86_400, null]);
    expect(await createToken(createKey, member, { name: "t", expiry: "never" })).toMatchObject({
      ok: true,
      expiresAt: null,
    });
  });

  test("rejects a missing or long name and an unknown expiry, without creating", async () => {
    const blank = await createToken(createKey, member, { name: "   ", expiry: "90" });
    expect(blank).toMatchObject({ ok: false, fieldErrors: { name: expect.any(String) } });
    const long = await createToken(createKey, member, { name: "x".repeat(65), expiry: "90" });
    expect(long).toMatchObject({ ok: false, fieldErrors: { name: expect.any(String) } });
    const expiry = await createToken(createKey, member, { name: "t", expiry: "7" });
    expect(expiry).toMatchObject({ ok: false, fieldErrors: { expiry: expect.any(String) } });
    expect(await createToken(createKey, member, null)).toMatchObject({ ok: false });
    expect(calls).toEqual([]);
  });
});

describe("revokeToken", () => {
  type Row = { id: string; user_id: string };
  let rows: Row[];
  let queries: string[];

  const db = {
    async query(sql: string, params: unknown[] = []): Promise<{ rows: never[] }> {
      queries.push(sql.split(/\s+/).slice(0, 3).join(" "));
      if (sql.startsWith("DELETE FROM api_tokens")) {
        const [id, owner] = params;
        const hit = rows.filter((r) => r.id === id && (owner === null || r.user_id === owner));
        rows = rows.filter((r) => !hit.includes(r));
        return { rows: hit.map((r) => ({ id: r.id })) as never[] };
      }
      if (sql.startsWith("SELECT 1 FROM api_tokens")) {
        return { rows: rows.filter((r) => r.id === params[0]).map(() => ({})) as never[] };
      }
      throw new Error(`unexpected query: ${sql}`);
    },
  };

  beforeEach(() => {
    queries = [];
    rows = [
      { id: MEMBER_TOKEN, user_id: MEMBER },
      { id: OTHER_TOKEN, user_id: OTHER },
    ];
  });

  test("a member revokes their own", async () => {
    expect(await revokeToken(db, member, MEMBER_TOKEN)).toEqual({ ok: true });
    expect(rows.map((r) => r.id)).toEqual([OTHER_TOKEN]);
  });

  test("a member can't revoke someone else's", async () => {
    expect(await revokeToken(db, member, OTHER_TOKEN)).toEqual({
      ok: false,
      error: TOKEN_ERRORS.forbidden,
    });
    expect(rows).toHaveLength(2);
  });

  test("an admin revokes anyone's", async () => {
    expect(await revokeToken(db, admin, OTHER_TOKEN)).toEqual({ ok: true });
    expect(await revokeToken(db, admin, MEMBER_TOKEN)).toEqual({ ok: true });
    expect(rows).toEqual([]);
  });

  test("an unknown token is not found, for admins too", async () => {
    expect(await revokeToken(db, admin, UNKNOWN)).toEqual({
      ok: false,
      error: TOKEN_ERRORS.notFound,
    });
    expect(await revokeToken(db, member, UNKNOWN)).toEqual({
      ok: false,
      error: TOKEN_ERRORS.notFound,
    });
  });

  test("a malformed id is not found, without touching the database", async () => {
    for (const id of ["", "not-a-uuid", 42, null]) {
      expect(await revokeToken(db, admin, id)).toEqual({
        ok: false,
        error: TOKEN_ERRORS.notFound,
      });
    }
    expect(queries).toEqual([]);
  });
});
