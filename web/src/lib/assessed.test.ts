/// <reference types="bun" />

import { describe, expect, test } from "bun:test";
import { assessedSql, isAssessed, releaseStatusOf } from "./assessed";

// Same table as server/internal/matcher/ecosystems_test.go TestAssessed:
// the mirror must agree with Go.
const CASES: [string, string, string, boolean | null, boolean][] = [
  ["deb", "debian", "bookworm", true, true],
  ["deb", "ubuntu", "jammy", true, true],
  ["apk", "alpine", "3.22", true, true],
  ["deb", "debian", "buster", false, false], // out of support: advisories not imported
  ["deb", "debian", "sid", null, false], // not in distro_releases
  ["apk", "alpine", "3.18", false, false],
  ["deb", "debian", "", true, false], // release unknown
  ["apk", "debian", "12", true, false],
  ["deb", "alpine", "3.22", true, false],
  ["rpm", "rhel", "9", true, false],
  ["npm", "", "", null, false],
  ["homebrew", "", "", null, false],
];

describe("isAssessed", () => {
  test.each(CASES)("%s %s %s supported=%p", (eco, distro, release, supported, want) => {
    expect(isAssessed(eco, distro, release, supported)).toBe(want);
  });
});

describe("releaseStatusOf", () => {
  test("supported, out of support, unknown", () => {
    expect(releaseStatusOf(true)).toBe("supported");
    expect(releaseStatusOf(false)).toBe("out_of_support");
    expect(releaseStatusOf(null)).toBe("unknown");
  });
});

describe("assessedSql", () => {
  test("requires a supported release for distro packages", () => {
    const sql = assessedSql("e", "d", "r", "s");
    expect(sql).toContain("(e = 'deb' AND d IN ('debian', 'ubuntu'))");
    expect(sql).toContain("(e = 'apk' AND d IN ('alpine'))");
    expect(sql).toContain("(d = '' OR (r <> '' AND coalesce(s, false)))");
  });
});
