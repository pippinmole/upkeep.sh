/// <reference types="bun" />

import { describe, expect, test } from "bun:test";

import { oauthQueryFrom, oauthRedirectUrl, safeReturnPath } from "./oauth-query";

describe("oauthQueryFrom", () => {
  test("null without a signature", () => {
    expect(oauthQueryFrom({})).toBeNull();
    expect(oauthQueryFrom({ client_id: "x" })).toBeNull();
  });

  test("keeps repeated parameters", () => {
    const q = oauthQueryFrom({ client_id: "c", ba_param: ["a", "b"], sig: "s" });
    expect(q).toBe("client_id=c&ba_param=a&ba_param=b&sig=s");
  });
});

describe("safeReturnPath", () => {
  test("only the consent page", () => {
    expect(safeReturnPath("/oauth/consent?client_id=x")).toBe("/oauth/consent?client_id=x");
    expect(safeReturnPath("/dashboard")).toBeNull();
    expect(safeReturnPath("https://evil.example/oauth/consent?")).toBeNull();
    expect(safeReturnPath("//evil.example")).toBeNull();
    expect(safeReturnPath(null)).toBeNull();
  });
});

describe("oauthRedirectUrl", () => {
  test("plain results and JSON responses", async () => {
    expect(await oauthRedirectUrl({ redirect: true, url: "http://localhost/cb?code=1" })).toBe(
      "http://localhost/cb?code=1",
    );
    expect(await oauthRedirectUrl({ redirect_uri: "http://localhost/cb" })).toBe(
      "http://localhost/cb",
    );
    expect(await oauthRedirectUrl(Response.json({ url: "/oauth/consent?x=1" }))).toBe(
      "/oauth/consent?x=1",
    );
    expect(await oauthRedirectUrl(Response.json({ error: "x" }, { status: 400 }))).toBeNull();
    expect(await oauthRedirectUrl({ token: null })).toBeNull();
  });
});
