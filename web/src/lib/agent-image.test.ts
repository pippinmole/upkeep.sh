/// <reference types="bun" />

import { readFileSync } from "fs";
import { join } from "path";
import { describe, expect, test } from "bun:test";

import { dockerRunCommand } from "@/app/dashboard/agents/register-agent-dialog";
import { DEFAULT_AGENT_IMAGE, resolveAgentImage } from "./agent-image";

describe("agent image pin", () => {
  test("is an exact pippinmole release, never :latest", () => {
    expect(DEFAULT_AGENT_IMAGE).toMatch(
      /^ghcr\.io\/pippinmole\/upkeep-agent:\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/,
    );
  });

  test("SW_AGENT_IMAGE overrides it; unset or blank keeps the default", () => {
    expect(resolveAgentImage({})).toBe(DEFAULT_AGENT_IMAGE);
    expect(resolveAgentImage({ SW_AGENT_IMAGE: "  " })).toBe(DEFAULT_AGENT_IMAGE);
    expect(resolveAgentImage({ SW_AGENT_IMAGE: "reg.example/upkeep-agent:1.2.3" })).toBe(
      "reg.example/upkeep-agent:1.2.3",
    );
  });

  test("the compose example pins the same image", () => {
    const compose = readFileSync(
      join(import.meta.dir, "../../../agent/docker-compose.example.yml"),
      "utf8",
    );
    expect(compose).toContain(`image: ${DEFAULT_AGENT_IMAGE}\n`);
  });
});

describe("dockerRunCommand", () => {
  test("runs the image it's given, as the last line", () => {
    const cmd = dockerRunCommand("https://upkeep.example", "tok", false, DEFAULT_AGENT_IMAGE);
    expect(cmd.trimEnd().split("\n").at(-1)?.trim()).toBe(DEFAULT_AGENT_IMAGE);
    expect(cmd).not.toContain(":latest");
  });

  test("has no image hard-coded in the dialog", () => {
    const cmd = dockerRunCommand("https://upkeep.example", "tok", true, "mirror/agent:9.9.9");
    expect(cmd).not.toContain("ghcr.io");
    expect(cmd.trimEnd().endsWith("mirror/agent:9.9.9")).toBe(true);
  });
});
