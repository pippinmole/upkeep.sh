import type { TableUrlOptions } from "@/components/data-table/url-params";

import type { ImageKey } from "./image-key";

// URL state of the fleet Vulnerabilities list and the host Vulnerabilities
// tab (server-driven DataTables), shared by the Server Components (parsing,
// SQL allowlists) and the client tables (writing the URL). Client-safe.
//
// Both list findings of two kinds (DOMAIN_MODEL.md §3.5, §3.6): host
// packages (`vulnerable_package`, fixed by upgrading the host) and
// container images (`vulnerable_image`, fixed by rebuilding or re-pulling
// the image). `?kind=` narrows to one; no `kind` = both. Their counts are
// shown per kind and never summed.

export const VULN_KINDS = ["package", "image"] as const;
export type VulnKind = (typeof VULN_KINDS)[number];

export const VULN_KIND_LABEL: Record<VulnKind, string> = {
  package: "Host packages",
  image: "Container images",
};

export const KIND_FACET_OPTIONS = VULN_KINDS.map((k) => ({ value: k, label: VULN_KIND_LABEL[k] }));

// findings.kind for a VulnKind.
export const FINDING_KIND: Record<VulnKind, string> = {
  package: "vulnerable_package",
  image: "vulnerable_image",
};

export const VULN_FIXES = ["available", "pro", "none"] as const;
export type VulnFix = (typeof VULN_FIXES)[number];

export const VULN_FIX_LABEL: Record<VulnFix, string> = {
  available: "Fix available",
  pro: "Fix requires Ubuntu Pro",
  none: "No fix yet",
};

export const FIX_FACET_OPTIONS = VULN_FIXES.map((f) => ({ value: f, label: VULN_FIX_LABEL[f] }));

// Fleet list: one row per (vuln_key, host packages) and per (vuln_key,
// image key). `seen` is the earliest first_seen_at for open rows and the
// latest resolved_at for resolved ones (the default sort there). Resolved
// rows have no Fix facet: the fix data is from when they were open.
export const FLEET_VULN_SORTS = ["severity", "vuln", "hosts", "seen"] as const;
export type FleetVulnSort = (typeof FLEET_VULN_SORTS)[number];

export function fleetVulnsTable(status: "open" | "resolved"): TableUrlOptions {
  return {
    sortKeys: FLEET_VULN_SORTS,
    filterKeys:
      status === "resolved" ? ["kind", "severity", "kev"] : ["kind", "severity", "kev", "fix"],
    defaultSort:
      status === "resolved" ? { id: "seen", desc: true } : { id: "severity", desc: true },
    defaultPageSize: 50,
  };
}

// Host tab: one row per finding. `seen` is first_seen_at for open
// findings and resolved_at for resolved ones (the default sort there).
export const HOST_VULN_SORTS = ["severity", "vuln", "seen"] as const;
export type HostVulnSort = (typeof HOST_VULN_SORTS)[number];

export function hostVulnsTable(status: "open" | "resolved"): TableUrlOptions {
  return {
    sortKeys: HOST_VULN_SORTS,
    filterKeys: ["kind", "severity", "kev", "fix"],
    defaultSort:
      status === "resolved" ? { id: "seen", desc: true } : { id: "severity", desc: true },
    defaultPageSize: 50,
  };
}

// Where a vulnerable package sits inside an image: its ecosystem (deb,
// apk, rpm, golang, npm, pypi, ...) and the paths the SBOM found it at
// (image_software.paths: the binary or manifest for language packages,
// only the package database for distro ones). Null when the image's
// list has no image_sbom_vulns row for it (not scored yet).
export type ImageOrigin = { ecosystem: string; paths: string[] };

// Where an image finding lives, as the Where column shows it.
export type ImageWhere = ImageKey & {
  refs: string[]; // findings.image_refs (repo:tag, else repo@digest)
  containers: string[]; // findings.container_names
};
