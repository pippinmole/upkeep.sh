/// <reference types="bun" />

import { describe, expect, test } from "bun:test";

import { inlineCodeSegments, sentenceCase, splitFirstSentence } from "@/lib/collector-message";

const HOST_MOUNT =
  "host unix sockets reachable under /host: run/docker.sock. Anything that can connect() to them controls the host (a read-only mount doesn't stop connect()), whether or not Docker collection is enabled. The host mount is recursive: mount the host's / non-recursively, as in agent/docker-compose.example.yml (compose `bind: {recursive: disabled}`, or docker run --mount ...,bind-recursive=disabled; a docker CLI older than 25 spells it bind-nonrecursive=true).";

describe("sentenceCase", () => {
  test("capitalizes a leading plain word", () => {
    expect(sentenceCase("host unix sockets")).toBe("Host unix sockets");
    expect(sentenceCase("timeout")).toBe("Timeout");
  });
  test("leaves paths and identifiers alone", () => {
    expect(sentenceCase("etc/machine-id is empty")).toBe("etc/machine-id is empty");
    expect(sentenceCase("dpkg-query: not found")).toBe("dpkg-query: not found");
    expect(sentenceCase("/proc/net/tcp missing")).toBe("/proc/net/tcp missing");
    expect(sentenceCase("")).toBe("");
  });
});

describe("splitFirstSentence", () => {
  test("splits the host_mount message after its first sentence", () => {
    const { summary, rest } = splitFirstSentence(HOST_MOUNT);
    expect(summary).toBe("host unix sockets reachable under /host: run/docker.sock.");
    expect(rest.startsWith("Anything that can connect()")).toBe(true);
  });
  test("single sentence has no rest", () => {
    expect(splitFirstSentence("etc/machine-id is empty")).toEqual({
      summary: "etc/machine-id is empty",
      rest: "",
    });
  });
  test("ignores periods in file names, parentheses and code", () => {
    expect(splitFirstSentence("see a.yml (e.g. This) and `x. Y` done").rest).toBe("");
  });
});

describe("inlineCodeSegments", () => {
  test("marks backtick spans as code", () => {
    expect(inlineCodeSegments("compose `bind: {}`, or x")).toEqual([
      { code: false, text: "compose " },
      { code: true, text: "bind: {}" },
      { code: false, text: ", or x" },
    ]);
  });
  test("keeps an unmatched backtick literal", () => {
    expect(inlineCodeSegments("a `b")).toEqual([{ code: false, text: "a `b" }]);
  });
});
