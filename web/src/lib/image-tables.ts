import type { TableUrlOptions } from "@/components/data-table/url-params";

import { SEVERITIES, SEVERITY_LABEL } from "./severity";

// URL state of the image detail page's two server-driven tables, shared by
// the Server Component (parsing, SQL allowlists) and the client tables
// (writing the URL). Client-safe. Both tabs use the same generic keys
// (?q, ?page, ?sort, ?size) plus one key per facet; switching tabs drops
// them.

export const IMAGE_PACKAGE_STATUSES = [
  "vulnerable",
  "not-assessed",
  "pending",
  "no-known",
] as const;
export type ImagePackageStatus = (typeof IMAGE_PACKAGE_STATUSES)[number];

export const IMAGE_PACKAGE_STATUS_LABEL: Record<ImagePackageStatus, string> = {
  vulnerable: "Vulnerable",
  "not-assessed": "Not assessed",
  pending: "Not matched yet",
  "no-known": "No known vulnerabilities",
};

export const IMAGE_PACKAGE_SORTS = ["status", "name", "ecosystem"] as const;
export type ImagePackageSort = (typeof IMAGE_PACKAGE_SORTS)[number];

export const PACKAGES_TABLE: TableUrlOptions = {
  sortKeys: IMAGE_PACKAGE_SORTS,
  filterKeys: ["ecosystem", "status"],
  defaultSort: { id: "status", desc: true },
  defaultPageSize: 50,
};

export const IMAGE_VULN_SORTS = ["severity", "vuln", "package", "epss", "cvss"] as const;
export type ImageVulnSort = (typeof IMAGE_VULN_SORTS)[number];

export const IMAGE_VULN_FIXES = ["available", "pro", "none"] as const;
export type ImageVulnFix = (typeof IMAGE_VULN_FIXES)[number];

export const IMAGE_VULN_FIX_LABEL: Record<ImageVulnFix, string> = {
  available: "Fix available",
  pro: "Fix requires Ubuntu Pro",
  none: "No fix yet",
};

export const VULNS_TABLE: TableUrlOptions = {
  sortKeys: IMAGE_VULN_SORTS,
  filterKeys: ["severity", "kev", "fix"],
  defaultSort: { id: "severity", desc: true },
  defaultPageSize: 50,
};

// ?kev=1 (a one-option facet).
export const KEV_FACET_OPTIONS = [{ value: "1", label: "Known exploited (KEV)" }];

export const SEVERITY_FACET_OPTIONS = SEVERITIES.map((s) => ({
  value: s,
  label: SEVERITY_LABEL[s],
}));
