/// <reference types="bun" />

import { describe, expect, test } from "bun:test";
import { advisoryUrl } from "./severity";

describe("advisoryUrl", () => {
  test.each([
    ["DSA-5532-1", "https://security-tracker.debian.org/tracker/DSA-5532-1"],
    ["CVE-2021-23337", "https://www.cve.org/CVERecord?id=CVE-2021-23337"],
    ["GHSA-35jh-r3h4-6jhm", "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm"],
    ["PYSEC-2021-19", "https://osv.dev/vulnerability/PYSEC-2021-19"],
    ["GO-2024-2687", "https://osv.dev/vulnerability/GO-2024-2687"],
    ["GHSA-bad", null],
    ["MAL-2024-1", null],
  ])("%s", (id, want) => {
    expect(advisoryUrl(id)).toBe(want);
  });
});
