/// <reference types="bun" />

import { beforeEach, describe, expect, test } from "bun:test";

import { type Db, REVOKE_ERRORS, revokeConsent } from "./revoke";

// revokeConsent against an in-memory fake of the OAuth tables: the SQL is
// the real module's, the fake applies it to rows, and a rollback restores
// the snapshot taken at BEGIN.

const ADMIN = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const MEMBER = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const OTHER = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const CLAUDE = "https://claude.ai/oauth/claude-code-client-metadata";
const ELSE = "https://example.com/client.json";

const MEMBER_CONSENT = "11111111-1111-4111-8111-111111111111";
const OTHER_CONSENT = "22222222-2222-4222-8222-222222222222";
const UNKNOWN = "99999999-9999-4999-8999-999999999999";

type Row = { id: string; client_id: string; user_id: string | null };
type Tables = { consents: Row[]; access: Row[]; refresh: Row[] };

let tables: Tables;
let snapshot: Tables | null;
let log: string[];

const clone = (t: Tables): Tables => structuredClone(t);

// Typed loosely: the fake returns whichever rows the query asks for.
const db = {
  async query(sql: string, params: unknown[] = []): Promise<{ rows: never[] }> {
    log.push(sql.split(/\s+/).slice(0, 3).join(" "));
    if (sql === "BEGIN") {
      snapshot = clone(tables);
      return { rows: [] };
    }
    if (sql === "COMMIT") {
      snapshot = null;
      return { rows: [] };
    }
    if (sql === "ROLLBACK") {
      if (snapshot) tables = snapshot;
      snapshot = null;
      return { rows: [] };
    }
    if (sql.startsWith("SELECT client_id, user_id FROM oauth_consents")) {
      return { rows: tables.consents.filter((c) => c.id === params[0]) as never[] };
    }
    const table = sql.startsWith("DELETE FROM oauth_access_tokens")
      ? "access"
      : sql.startsWith("DELETE FROM oauth_refresh_tokens")
        ? "refresh"
        : sql.startsWith("DELETE FROM oauth_consents")
          ? "consents"
          : null;
    if (!table) throw new Error(`unexpected query: ${sql}`);
    const keep =
      table === "consents"
        ? (r: Row) => r.id !== params[0]
        : (r: Row) => !(r.client_id === params[0] && r.user_id === params[1]);
    tables[table] = tables[table].filter(keep);
    return { rows: [] };
  },
};

const row = (id: string, client_id: string, user_id: string): Row => ({ id, client_id, user_id });

beforeEach(() => {
  snapshot = null;
  log = [];
  tables = {
    consents: [
      row(MEMBER_CONSENT, CLAUDE, MEMBER),
      row(OTHER_CONSENT, CLAUDE, OTHER),
      row("33333333-3333-4333-8333-333333333333", ELSE, MEMBER),
    ],
    access: [
      row("a1", CLAUDE, MEMBER),
      row("a2", CLAUDE, MEMBER),
      row("a3", CLAUDE, OTHER),
      row("a4", ELSE, MEMBER),
    ],
    refresh: [row("r1", CLAUDE, MEMBER), row("r2", CLAUDE, OTHER), row("r3", ELSE, MEMBER)],
  };
});

const ids = (rows: Row[]) => rows.map((r) => r.id).sort();
const member = { userId: MEMBER, isAdmin: false };
const admin = { userId: ADMIN, isAdmin: true };

describe("revokeConsent", () => {
  test("a member revokes their own: consent and that client's tokens go, nothing else", async () => {
    expect(await revokeConsent(db, member, MEMBER_CONSENT)).toEqual({ ok: true });
    expect(tables.consents.map((c) => c.id)).not.toContain(MEMBER_CONSENT);
    expect(ids(tables.access)).toEqual(["a3", "a4"]);
    expect(ids(tables.refresh)).toEqual(["r2", "r3"]);
    expect(log.at(-1)).toBe("COMMIT");
  });

  test("a member can't revoke someone else's", async () => {
    expect(await revokeConsent(db, member, OTHER_CONSENT)).toEqual({
      ok: false,
      error: REVOKE_ERRORS.forbidden,
    });
    expect(tables.consents).toHaveLength(3);
    expect(tables.access).toHaveLength(4);
    expect(tables.refresh).toHaveLength(3);
    expect(log).not.toContain("COMMIT");
    expect(log.some((q) => q.startsWith("DELETE"))).toBe(false);
  });

  test("an admin revokes anyone's", async () => {
    expect(await revokeConsent(db, admin, OTHER_CONSENT)).toEqual({ ok: true });
    expect(tables.consents.map((c) => c.id)).not.toContain(OTHER_CONSENT);
    expect(ids(tables.access)).toEqual(["a1", "a2", "a4"]);
    expect(ids(tables.refresh)).toEqual(["r1", "r3"]);
  });

  test("an unknown consent is not found, for admins too", async () => {
    expect(await revokeConsent(db, admin, UNKNOWN)).toEqual({
      ok: false,
      error: REVOKE_ERRORS.notFound,
    });
    expect(log).toEqual(["BEGIN", "SELECT client_id, user_id", "ROLLBACK"]);
  });

  test("a malformed id is not found, without touching the database", async () => {
    for (const id of ["", "not-a-uuid", 42, null]) {
      expect(await revokeConsent(db, admin, id)).toEqual({
        ok: false,
        error: REVOKE_ERRORS.notFound,
      });
    }
    expect(log).toEqual([]);
  });

  test("a failure part way rolls the whole revoke back", async () => {
    const failing: Db = {
      async query(sql: string, params?: unknown[]) {
        if (sql.startsWith("DELETE FROM oauth_refresh_tokens")) throw new Error("boom");
        return db.query(sql, params) as never;
      },
    };
    await expect(revokeConsent(failing, member, MEMBER_CONSENT)).rejects.toThrow("boom");
    expect(tables.access).toHaveLength(4);
    expect(tables.consents).toHaveLength(3);
  });
});
