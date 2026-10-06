/// <reference types="bun" />

import { describe, expect, test } from "bun:test";

import {
  parseImageRef,
  repoForms,
  resolveHost,
  resolveImage,
  type ResolvedHost,
  type ResolvedImage,
} from "./resolve";
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

const img = (arch: string, refs = ["app:1"]): ResolvedImage => ({
  key: { imageId: "sha256:abc", os: "linux", arch, variant: "" },
  refs,
});

describe("resolveImage", () => {
  test("one match: that image; the platform reaches the lookup", async () => {
    let seen: unknown;
    const found = await resolveImage("ws", "app:1", "linux/arm64", async (_ws, _ref, p) => {
      seen = p;
      return [img("arm64")];
    });
    expect(found).toEqual(img("arm64"));
    expect(seen).toEqual({ os: "linux", arch: "arm64", variant: "" });
  });

  test("no match: a tool error naming the reference and pointing at list_images", async () => {
    const err = await resolveImage("ws", "nope:1", null, async () => []).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toContain('reference "nope:1"');
    expect((err as Error).message).toContain("list_images");
  });

  test("several: a tool error listing each candidate's id and platform", async () => {
    const err = await resolveImage("ws", "sha256:abc", null, async () => [
      img("amd64"),
      img("arm64", []),
    ]).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toContain(
      "app:1 (linux/amd64): sha256:abc platform linux/amd64; abc (linux/arm64): sha256:abc platform linux/arm64",
    );
  });

  test("a malformed platform is refused before the lookup", async () => {
    let called = false;
    const err = await resolveImage("ws", "app:1", "amd64", async () => {
      called = true;
      return [];
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toContain("os/arch[/variant]");
    expect(called).toBe(false);
  });
});

describe("image references", () => {
  test("Docker Hub names match with or without docker.io/ and library/", () => {
    expect(repoForms("nginx").toSorted()).toEqual(
      ["docker.io/library/nginx", "docker.io/nginx", "library/nginx", "nginx"].toSorted(),
    );
    expect(repoForms("docker.io/library/nginx")).toContain("nginx");
    expect(repoForms("org/app")).toEqual(["org/app", "docker.io/org/app"]);
  });

  test("other registries keep their host", () => {
    expect(repoForms("ghcr.io/org/app")).toEqual(["ghcr.io/org/app"]);
    expect(repoForms("localhost:5000/app")).toEqual(["localhost:5000/app"]);
  });

  test("tag, digest and bare repository references", () => {
    expect(parseImageRef("nginx:1.27").tags).toContain("nginx:1.27");
    expect(parseImageRef("localhost:5000/app")).toEqual({
      tags: [],
      digests: [],
      repos: ["localhost:5000/app"],
    });
    expect(parseImageRef("ghcr.io/org/app@sha256:ff")).toEqual({
      tags: [],
      digests: ["ghcr.io/org/app@sha256:ff"],
      repos: [],
    });
  });
});
