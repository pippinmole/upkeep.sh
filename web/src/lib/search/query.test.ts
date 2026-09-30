/// <reference types="bun" />

import { describe, expect, test } from "bun:test";

import { MAX_QUERY_LENGTH, escapeLike, exactVulnId, normalizeQuery, searchTerms } from "./query";

describe("normalizeQuery", () => {
  test("trims and collapses whitespace", () => {
    expect(normalizeQuery("  web   01 ")).toBe("web 01");
  });

  test("too short, empty or missing is null", () => {
    expect(normalizeQuery("a")).toBeNull();
    expect(normalizeQuery("  a  ")).toBeNull();
    expect(normalizeQuery("")).toBeNull();
    expect(normalizeQuery(null)).toBeNull();
    expect(normalizeQuery(undefined)).toBeNull();
    expect(normalizeQuery("ab")).toBe("ab");
  });

  test("caps the length", () => {
    expect(normalizeQuery("x".repeat(500))).toHaveLength(MAX_QUERY_LENGTH);
  });
});

describe("escapeLike", () => {
  test("wildcards and the escape character match themselves", () => {
    expect(escapeLike("50%_off\\")).toBe("50\\%\\_off\\\\");
    expect(escapeLike("openssl")).toBe("openssl");
  });
});

describe("exactVulnId", () => {
  test("canonical upper case", () => {
    expect(exactVulnId("cve-2024-3094")).toBe("CVE-2024-3094");
    expect(exactVulnId(" CVE-2021-44228 ")).toBe("CVE-2021-44228");
    expect(exactVulnId("usn-6500-1")).toBe("USN-6500-1");
    expect(exactVulnId("dsa-5532-1")).toBe("DSA-5532-1");
    expect(exactVulnId("DLA-3600-1")).toBe("DLA-3600-1");
    expect(exactVulnId("ubuntu-cve-2024-1234")).toBe("UBUNTU-CVE-2024-1234");
    expect(exactVulnId("rhsa-2024:1234")).toBe("RHSA-2024:1234");
  });

  test("GHSA keeps its lower-case tail", () => {
    expect(exactVulnId("ghsa-ABCD-1234-wxyz")).toBe("GHSA-abcd-1234-wxyz");
  });

  test("partial ids and other text are not exact ids", () => {
    expect(exactVulnId("CVE-2024")).toBeNull();
    expect(exactVulnId("CVE-2024-")).toBeNull();
    expect(exactVulnId("openssl")).toBeNull();
    expect(exactVulnId("CVE-2024-3094 openssl")).toBeNull();
  });
});

describe("searchTerms", () => {
  test("builds escaped ILIKE patterns and the lower-case exact key", () => {
    expect(searchTerms(" Web_01 ")).toEqual({
      q: "Web_01",
      lower: "web_01",
      contains: "%Web\\_01%",
      prefix: "Web\\_01%",
      vulnId: null,
    });
  });

  test("an exact CVE id carries its canonical form", () => {
    expect(searchTerms("cve-2024-3094")?.vulnId).toBe("CVE-2024-3094");
  });

  test("null below the minimum length", () => {
    expect(searchTerms("x")).toBeNull();
  });
});
