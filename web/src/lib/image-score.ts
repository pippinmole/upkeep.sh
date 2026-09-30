import { isAssessedDistro, releaseStatusOf } from "./assessed";
import type { Severity, SeverityCounts } from "./severity";

// An image key's package list status and score as one user sees it: the
// image_scores(user) read model (migration 0015, DOMAIN_MODEL.md §2.6
// "Image findings and scores"), plus whether the list's distro release is
// still supported. Client-safe (types and pure functions only); the SQL is
// in queries-image-scores.ts.

// server/internal/store/imagesbom_fetch.go SBOMReason*: exact strings.
export const SBOM_REASON_PRIVATE = "private or local image, needs the agent";

export type ImageScore = {
  // ok = an effective list; unavailable / error = none, `reason` says why;
  // none = nothing attempted yet.
  listStatus: "ok" | "unavailable" | "error" | "none";
  listReason: string | null;
  listSource: string | null; // attestation | server-syft | agent-syft
  distro: string | null; // os-release ID of the list ('debian', 'alpine')
  release: string | null; // key its distro packages were interned under
  distroName: string | null; // PRETTY_NAME
  // distro_releases.supported for (distro, release); null = not in the table.
  releaseSupported: boolean | null;
  releaseEol: string | null; // distro_releases.eol_date, YYYY-MM-DD
  distroVersion: string | null; // os-release VERSION_ID ("10"), for labels
  // False while the ok list is being matched / scored: counts are stale or null.
  scored: boolean;
  packages: number | null;
  notAssessed: number | null;
  vulns: number | null;
  worst: Severity | null; // null with vulns 0 = no known vulnerabilities
  counts: SeverityCounts;
  kev: number;
  fixable: number;
  maxCvss: number | null;
};

// What to show for an image instead of (or with) its counts. Ordered by
// how the list got there; every "no list" state says why.
export type ImageScoreState =
  | { kind: "not_inspected" } // no platform known: never inspected on a host
  | { kind: "none"; local: boolean } // never attempted; local = no repo digest anywhere
  | { kind: "unavailable"; reason: string; needsAgent: boolean }
  | { kind: "error"; reason: string }
  | { kind: "scoring" } // ok list, score not computed yet
  // ok list whose distro release isn't assessed: no vulnerabilities means
  // nothing here, so never "clean". `why`: the release is out of support
  // (distro_releases.supported = false; eol when known), not a release
  // distro_releases knows, or a distro whose advisories aren't imported.
  | {
      kind: "release_not_assessed";
      why: ReleaseNotAssessed;
      distro: string;
      release: string | null;
      label: string; // "Debian 10 (buster)"
      eol: string | null;
    }
  | { kind: "vulnerable" }
  // No known vulnerabilities; partial = some packages aren't assessed.
  | { kind: "no_known"; partial: boolean };

export type ReleaseNotAssessed = "out_of_support" | "unknown_release" | "distro_not_assessed";

// Why an ok list's distro release isn't assessed (matcher.Assessed); null
// when it is, or the list has no distro (distroless: its packages count on
// their own).
export function releaseNotAssessed(
  distro: string | null,
  supported: boolean | null,
): ReleaseNotAssessed | null {
  if (!distro) return null;
  if (!isAssessedDistro(distro)) return "distro_not_assessed";
  const st = releaseStatusOf(supported);
  if (st === "supported") return null;
  return st === "out_of_support" ? "out_of_support" : "unknown_release";
}

// Short label of a release_not_assessed state, for cells and badges.
export const RELEASE_NOT_ASSESSED_LABEL: Record<ReleaseNotAssessed, string> = {
  out_of_support: "Release out of support",
  unknown_release: "Release not recognised",
  distro_not_assessed: "Distro not assessed",
};

// "Debian 10 (buster)" / "Alpine 3.18": PRETTY_NAME when the list has
// one, else the distro and VERSION_ID, plus the codename if not in it.
export function releaseName(
  distro: string,
  version: string | null,
  release: string | null,
  prettyName: string | null,
): string {
  const name =
    prettyName ||
    [distro.charAt(0).toUpperCase() + distro.slice(1), version].filter(Boolean).join(" ");
  return release && !name.includes(release) ? `${name} (${release})` : name;
}

// One sentence on why a release isn't assessed, for titles and notes.
export function releaseNotAssessedText(
  why: ReleaseNotAssessed,
  label: string,
  eol: string | null,
  formatDate: (d: string) => string,
): string {
  switch (why) {
    case "out_of_support":
      return `${label} is out of support${eol ? ` since ${formatDate(eol)}` : ""}: its advisories aren't imported, so its packages aren't matched.`;
    case "unknown_release":
      return `${label} isn't a release the matcher knows, so its packages aren't matched.`;
    case "distro_not_assessed":
      return `${label}: this distribution's advisories aren't imported, so its packages aren't matched.`;
  }
}

export function imageScoreState(
  s: ImageScore | null,
  ctx: { inspected: boolean; hasRepoDigest: boolean },
): ImageScoreState {
  if (!ctx.inspected || !s) return { kind: "not_inspected" };
  switch (s.listStatus) {
    case "none":
      return { kind: "none", local: !ctx.hasRepoDigest };
    case "unavailable":
      return {
        kind: "unavailable",
        reason: s.listReason ?? "unavailable",
        needsAgent: s.listReason === SBOM_REASON_PRIVATE,
      };
    case "error":
      return { kind: "error", reason: s.listReason ?? "error" };
  }
  if (!s.scored) return { kind: "scoring" };
  if ((s.vulns ?? 0) > 0) return { kind: "vulnerable" };
  const why = releaseNotAssessed(s.distro, s.releaseSupported);
  if (why && s.distro) {
    return {
      kind: "release_not_assessed",
      why,
      distro: s.distro,
      release: s.release,
      label: releaseName(s.distro, s.distroVersion, s.release, s.distroName),
      eol: why === "out_of_support" ? s.releaseEol : null,
    };
  }
  return { kind: "no_known", partial: (s.notAssessed ?? 0) > 0 };
}
