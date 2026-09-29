import type { ImageScore } from "./image-score";
import { isSeverity } from "./severity";

// SQL side of image-score.ts: the columns of image_scores(user) (migration
// 0015) that the dashboard shows, as server/internal/store/imagescore_read.go
// reads them. Callers join
//
//   LEFT JOIN image_scores($user) s
//     ON s.image_id = … AND s.os = … AND s.arch = … AND s.variant = …
//   ${RELEASE_JOIN}
//
// restricted to image keys on the user's own hosts (image_scores has a row
// for every container_images key, fleet-wide). The function is a single
// STABLE SQL SELECT, so the planner inlines it and the key conditions
// drive the lookups.

export const IMAGE_SCORE_COLUMNS = `
  s.list_status, s.list_reason, s.list_source, s.distro, s.release, s.distro_name,
  dr.supported AS release_supported, to_char(dr.eol_date, 'YYYY-MM-DD') AS release_eol,
  sbst.distro_version, s.scored, s.package_count, s.not_assessed_count,
  s.vuln_count, s.worst_severity, s.critical_count, s.high_count, s.medium_count,
  s.unknown_count, s.low_count, s.negligible_count, s.kev_count, s.fixable_count,
  s.max_cvss`;

// The list's distro_releases row (supported, EOL) and its os-release
// VERSION_ID (image_scores has the codename only).
export const RELEASE_JOIN = `LEFT JOIN distro_releases dr ON dr.distro = s.distro AND dr.codename = s.release
  LEFT JOIN image_sbom_state sbst ON sbst.id = s.sbom_id`;

export type ImageScoreDbRow = {
  list_status: string | null;
  list_reason: string | null;
  list_source: string | null;
  distro: string | null;
  release: string | null;
  distro_name: string | null;
  release_supported: boolean | null;
  release_eol: string | null;
  distro_version: string | null;
  scored: boolean | null;
  package_count: number | null;
  not_assessed_count: number | null;
  vuln_count: number | null;
  worst_severity: string | null;
  critical_count: number | null;
  high_count: number | null;
  medium_count: number | null;
  unknown_count: number | null;
  low_count: number | null;
  negligible_count: number | null;
  kev_count: number | null;
  fixable_count: number | null;
  max_cvss: string | null;
};

const LIST_STATUSES = ["ok", "unavailable", "error", "none"] as const;

// null when the LEFT JOIN found no container_images row (image not
// inspected, so its key isn't known).
export function mapImageScore(r: ImageScoreDbRow): ImageScore | null {
  const status = LIST_STATUSES.find((x) => x === r.list_status);
  if (!status) return null;
  return {
    listStatus: status,
    listReason: r.list_reason,
    listSource: r.list_source,
    distro: r.distro,
    release: r.release,
    distroName: r.distro_name,
    releaseSupported: r.release_supported,
    releaseEol: r.release_eol,
    distroVersion: r.distro_version,
    scored: r.scored === true,
    packages: r.package_count,
    notAssessed: r.not_assessed_count,
    vulns: r.vuln_count,
    worst: isSeverity(r.worst_severity) ? r.worst_severity : null,
    counts: {
      critical: r.critical_count ?? 0,
      high: r.high_count ?? 0,
      medium: r.medium_count ?? 0,
      unknown: r.unknown_count ?? 0,
      low: r.low_count ?? 0,
      negligible: r.negligible_count ?? 0,
    },
    kev: r.kev_count ?? 0,
    fixable: r.fixable_count ?? 0,
    maxCvss: r.max_cvss === null ? null : Number(r.max_cvss),
  };
}
