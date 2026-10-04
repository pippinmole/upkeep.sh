/// <reference types="bun" />

import { describe, expect, test } from "bun:test";

import { resolveHost, type ResolvedHost } from "./resolve";
import { ToolError } from "./tool";

const web = (id: string, label: string | null = null): ResolvedHost => ({
  id,
  hostname: "web-01",
  label,
});

describe("resolveHost", () => {
  test("one match: that host", async () => {
    expect(await resolveHost("ws", "web-01", async () => [web("a")])).toEqual(web("a"));
  });

  test("no match: a tool error naming the reference", async () => {
    const err = await resolveHost("ws", "nope", async () => []).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toContain('"nope"');
  });

  test("an ambiguous hostname: a tool error listing the candidates' ids", async () => {
    const err = await resolveHost("ws", "web-01", async () => [web("a", "eu"), web("b")]).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toContain("web-01 (eu): a; web-01: b");
  });
});
