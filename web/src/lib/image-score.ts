import { isAssessedDistro } from "./assessed";
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
  // ok list whose distro release isn't assessed (out of support, or a
  // distro we don't import): no vulnerabilities means nothing here.
  | { kind: "release_not_assessed"; distro: string; release: string | null }
  | { kind: "vulnerable" }
  // No known vulnerabilities; partial = some packages aren't assessed.
  | { kind: "no_known"; partial: boolean };

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
  if (s.distro && (!isAssessedDistro(s.distro) || s.releaseSupported !== true)) {
    return { kind: "release_not_assessed", distro: s.distro, release: s.release };
  }
  return { kind: "no_known", partial: (s.notAssessed ?? 0) > 0 };
}
