/// <reference types="bun" />

import { APIError } from "better-auth/api";
import { beforeEach, describe, expect, mock, test } from "bun:test";

// signInWithPassword and decideConsent against a fake Better Auth. Without a
// Request, authServer.api throws an APIError on failure; with one (an MCP
// sign-in), it answers with an error Response instead. Both must reach the
// same message.
class Redirect extends Error {
  constructor(readonly url: string) {
    super(`redirect ${url}`);
  }
}

let answer: () => Promise<unknown>;
const signInUsername = mock(() => answer());
const oauth2Consent = mock(() => answer());

mock.module("next/headers", () => ({ headers: async () => new Headers() }));
mock.module("next/navigation", () => ({
  redirect: (url: string) => {
    throw new Redirect(url);
  },
}));
mock.module("@/lib/auth", () => ({ authServer: { api: { signInUsername, oauth2Consent } } }));
mock.module("@/lib/viewer", () => ({ getViewer: async () => ({ mustChangePassword: false }) }));

const { signInWithPassword } = await import("./actions");
const { decideConsent } = await import("../oauth/consent/actions");

const OAUTH_QUERY = "client_id=c&sig=s&exp=1";

function form(fields: Record<string, string>): FormData {
  const f = new FormData();
  for (const [k, v] of Object.entries(fields)) f.set(k, v);
  return f;
}

const thrown = (status: "UNAUTHORIZED" | "BAD_REQUEST", body: Record<string, string>) => () =>
  Promise.reject(new APIError(status, body));
const response = (status: number, body: unknown) => () =>
  Promise.resolve(Response.json(body, { status }));

async function redirectOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (err) {
    if (err instanceof Redirect) return err.url;
    throw err;
  }
  throw new Error("expected a redirect");
}

beforeEach(() => {
  signInUsername.mockClear();
  oauth2Consent.mockClear();
});

describe("signInWithPassword", () => {
  const signIn = (fields: Record<string, string>) =>
    signInWithPassword({ error: null }, form({ username: " ada ", password: "pw", ...fields }));

  test("wrong credentials, thrown", async () => {
    answer = thrown("UNAUTHORIZED", { code: "INVALID_USERNAME_OR_PASSWORD" });
    expect(await signIn({})).toEqual({ error: "Wrong username or password.", username: "ada" });
  });

  test("wrong credentials during an MCP sign-in, as a Response", async () => {
    answer = response(401, { code: "INVALID_USERNAME_OR_PASSWORD" });
    expect(await signIn({ oauth_query: OAUTH_QUERY })).toEqual({
      error: "Wrong username or password.",
      username: "ada",
    });
  });

  test("a disabled account, as a Response", async () => {
    answer = response(403, { code: "ACCOUNT_DISABLED" });
    expect((await signIn({ oauth_query: OAUTH_QUERY })).error).toBe(
      "This account is disabled. Ask an administrator.",
    );
  });

  test("an expired sign-in link, as a Response", async () => {
    answer = response(400, { error: "invalid_signature" });
    expect((await signIn({ oauth_query: OAUTH_QUERY })).error).toBe(
      "This sign-in link has expired. Start the connection again from your app.",
    );
  });

  test("an error Response without a JSON body", async () => {
    answer = () => Promise.resolve(new Response("nope", { status: 500 }));
    expect((await signIn({ oauth_query: OAUTH_QUERY })).error).toBe(
      "Could not sign in. Please try again.",
    );
  });

  test("success without an oauth_query goes to the dashboard", async () => {
    answer = () => Promise.resolve({ token: "t" });
    expect(await redirectOf(signIn({}))).toBe("/dashboard");
  });

  test("success during an MCP sign-in continues the request", async () => {
    answer = response(200, { redirect: true, url: "/oauth/consent?x=1" });
    expect(await redirectOf(signIn({ oauth_query: OAUTH_QUERY }))).toBe("/oauth/consent?x=1");
  });
});

describe("decideConsent", () => {
  const decide = () =>
    decideConsent({ error: null }, form({ oauth_query: OAUTH_QUERY, decision: "allow" }));

  test("an expired request, thrown", async () => {
    answer = thrown("BAD_REQUEST", { error: "invalid_signature" });
    expect((await decide()).error).toBe(
      "This request has expired. Start the connection again from your app.",
    );
  });

  test("an expired request, as a Response", async () => {
    answer = response(400, { error: "invalid_signature" });
    expect((await decide()).error).toBe(
      "This request has expired. Start the connection again from your app.",
    );
  });

  test("any other refusal", async () => {
    answer = response(400, { error: "invalid_request" });
    expect((await decide()).error).toBe(
      "Could not complete the request. Start the connection again from your app.",
    );
  });

  test("allow redirects to the client", async () => {
    answer = response(200, { redirect_uri: "http://127.0.0.1:5555/cb?code=abc" });
    expect(await redirectOf(decide())).toBe("http://127.0.0.1:5555/cb?code=abc");
  });
});
