/// <reference types="bun" />

import { describe, expect, test } from "bun:test";
import { imageScoreState, type ImageScore } from "./image-score";
import { emptySeverityCounts } from "./severity";

// An ok, scored list with no matches; override per case.
function score(o: Partial<ImageScore>): ImageScore {
  return {
    listStatus: "ok",
    listReason: null,
    listSource: "attestation",
    distro: "debian",
    release: "bookworm",
    distroName: null,
    releaseSupported: true,
    releaseEol: null,
    distroVersion: "12",
    scored: true,
    packages: 10,
    notAssessed: 0,
    vulns: 0,
    worst: null,
    counts: emptySeverityCounts(),
    kev: 0,
    fixable: 0,
    maxCvss: null,
    ...o,
  };
}

const ctx = { inspected: true, hasRepoDigest: true };

describe("imageScoreState", () => {
  test("a supported release with no matches is clean", () => {
    expect(imageScoreState(score({}), ctx)).toEqual({ kind: "no_known", partial: false });
  });

  test("an out-of-support release is never clean, with its EOL date", () => {
    const st = imageScoreState(
      score({
        release: "buster",
        distroVersion: "10",
        releaseSupported: false,
        releaseEol: "2024-06-30",
        notAssessed: 10,
      }),
      ctx,
    );
    expect(st).toEqual({
      kind: "release_not_assessed",
      why: "out_of_support",
      distro: "debian",
      release: "buster",
      label: "Debian 10 (buster)",
      eol: "2024-06-30",
    });
  });

  test("a release not in distro_releases is not recognised", () => {
    const st = imageScoreState(score({ release: "sid", releaseSupported: null }), ctx);
    expect(st).toMatchObject({ kind: "release_not_assessed", why: "unknown_release", eol: null });
  });

  test("a distro whose advisories aren't imported", () => {
    const st = imageScoreState(
      score({ distro: "rhel", release: "9", distroName: "RHEL 9", releaseSupported: null }),
      ctx,
    );
    expect(st).toMatchObject({ why: "distro_not_assessed", label: "RHEL 9" });
  });

  test("no distro (distroless): packages count on their own", () => {
    const st = imageScoreState(score({ distro: null, release: null, notAssessed: 3 }), ctx);
    expect(st).toEqual({ kind: "no_known", partial: true });
  });

  test("vulnerabilities still show on an out-of-support release", () => {
    const st = imageScoreState(score({ releaseSupported: false, vulns: 2, worst: "high" }), ctx);
    expect(st.kind).toBe("vulnerable");
  });
});
