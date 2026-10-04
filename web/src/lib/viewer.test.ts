/// <reference types="bun" />

import { beforeEach, describe, expect, mock, test } from "bun:test";

// viewerForUser / getMcpViewer against a fake pool: the SQL is the real
// module's, the rows are the test's.
type UserRow = {
  role: string;
  must_change_password: boolean;
  disabled: boolean;
  email: string;
  name: string;
  username: string | null;
};

const USER = "11111111-1111-4111-8111-111111111111";
const CLIENT = "https://claude.ai/oauth/claude-code-client-metadata";
const WORKSPACE = "22222222-2222-4222-8222-222222222222";

let users: Record<string, UserRow>;
let clients: { clientId: string; userId: string; id: string; name: string }[];

const query = mock(async (sql: string, params: unknown[] = []) => {
  if (sql.includes("FROM workspaces")) return { rows: [{ id: WORKSPACE }] };
  if (sql.includes("FROM users")) {
    const u = users[String(params[0])];
    return { rows: u ? [u] : [] };
  }
  if (sql.includes("FROM oauth_clients")) {
    return {
      rows: clients
        .filter((c) => c.clientId === params[0] && c.userId === params[1])
        .map((c) => ({ id: c.id, name: c.name })),
    };
  }
  throw new Error(`unexpected query: ${sql}`);
});

mock.module("./db", () => ({ pool: { query } }));
mock.module("./auth", () => ({ auth: async () => null }));

const { getMcpViewer, viewerForUser } = await import("./viewer");

const member = (over: Partial<UserRow> = {}): UserRow => ({
  role: "member",
  must_change_password: false,
  disabled: false,
  email: "m@example.com",
  name: "M",
  username: "m",
  ...over,
});

beforeEach(() => {
  users = { [USER]: member() };
  clients = [{ clientId: CLIENT, userId: USER, id: "client-row-id", name: "Claude Code" }];
});

describe("viewerForUser", () => {
  test("an enabled user, with role and flags from users", async () => {
    users[USER] = member({ role: "admin" });
    expect(await viewerForUser(USER)).toMatchObject({
      userId: USER,
      workspaceId: WORKSPACE,
      role: "admin",
      isAdmin: true,
      mustChangePassword: false,
    });
  });

  test("null for an unknown user", async () => {
    expect(await viewerForUser("33333333-3333-4333-8333-333333333333")).toBeNull();
  });

  test("null for a disabled user", async () => {
    users[USER] = member({ disabled: true });
    expect(await viewerForUser(USER)).toBeNull();
  });

  test("null for an unknown role", async () => {
    users[USER] = member({ role: "owner" });
    expect(await viewerForUser(USER)).toBeNull();
  });
});

describe("getMcpViewer", () => {
  const claims = { sub: USER, azp: CLIENT, scope: "mcp:read offline_access" };

  test("resolves the user and the OAuth client", async () => {
    expect(await getMcpViewer(claims)).toMatchObject({
      userId: USER,
      role: "member",
      credential: {
        kind: "oauth",
        clientId: CLIENT,
        oauthClientId: "client-row-id",
        clientName: "Claude Code",
        scopes: ["mcp:read", "offline_access"],
      },
    });
  });

  test("a temporary password still resolves, flagged", async () => {
    users[USER] = member({ must_change_password: true });
    expect((await getMcpViewer(claims))?.mustChangePassword).toBe(true);
  });

  test("null (401) for a disabled user", async () => {
    users[USER] = member({ disabled: true });
    expect(await getMcpViewer(claims)).toBeNull();
  });

  test("null (401) for an unknown user", async () => {
    users = {};
    expect(await getMcpViewer(claims)).toBeNull();
  });

  test("null (401) when the consent or the client is gone", async () => {
    clients = [];
    expect(await getMcpViewer(claims)).toBeNull();
  });

  test("null for claims without a uuid subject or a client", async () => {
    expect(await getMcpViewer({ ...claims, sub: "not-a-uuid" })).toBeNull();
    expect(await getMcpViewer({ ...claims, sub: undefined })).toBeNull();
    expect(await getMcpViewer({ ...claims, azp: undefined })).toBeNull();
  });
});
