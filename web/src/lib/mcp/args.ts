import * as z from "zod";

import { SEVERITIES, type Severity } from "@/lib/severity";
import type { VulnKind } from "@/lib/vuln-tables";

// Argument schemas shared by the MCP tools (docs/MCP.md#tools), so every
// tool spells limit, severity and kind the same way.

export const DEFAULT_LIMIT = 15;
export const MAX_LIMIT = 100;

// Lists take a limit and report `truncated` rather than paging, so a client
// can't walk the whole database by accident.
export const limitArg = z
  .number()
  .int()
  .min(1)
  .max(MAX_LIMIT)
  .default(DEFAULT_LIMIT)
  .describe(`Maximum number of items to return (1-${MAX_LIMIT}, default ${DEFAULT_LIMIT})`);

export const severityEnum = z.enum(SEVERITIES);

export const minSeverityArg = severityEnum
  .optional()
  .describe(
    "Only vulnerabilities at this severity or worse. Most urgent first: " +
      `${SEVERITIES.join(" > ")} ("unknown" means not triaged yet and ranks above low)`,
  );

// The severity buckets at min or worse, in the dashboard's order; null (no
// filter) when min is absent.
export function severitiesAtLeast(min: Severity | undefined): Severity[] | null {
  if (!min) return null;
  return SEVERITIES.slice(0, SEVERITIES.indexOf(min) + 1);
}

// Host package findings (fixed by upgrading the host) or container image
// findings (fixed by rebuilding or re-pulling the image), or both.
export const KIND_ARGS = ["host", "image", "all"] as const;
export type KindArg = (typeof KIND_ARGS)[number];

export const kindArg = z
  .enum(KIND_ARGS)
  .default("all")
  .describe(
    '"host": packages installed on hosts (fixed by upgrading the host); "image": packages inside ' +
      'container images (fixed by rebuilding or re-pulling the image); "all" (default): both',
  );

// The dashboard's ?kind= facet for a kind argument; null = both.
export function vulnKinds(kind: KindArg): VulnKind[] | null {
  if (kind === "host") return ["package"];
  if (kind === "image") return ["image"];
  return null;
}

// The item kind a finding kind is reported as.
export function kindOf(kind: VulnKind): Exclude<KindArg, "all"> {
  return kind === "package" ? "host" : "image";
}

export const hostArg = z.string().trim().min(1).max(253).describe("A host's id or hostname");

export const kevOnlyArg = z
  .boolean()
  .default(false)
  .describe("Only vulnerabilities in CISA's Known Exploited Vulnerabilities catalog");

export const fixableOnlyArg = z
  .boolean()
  .default(false)
  .describe(
    'Only vulnerabilities with a fix available (the dashboard\'s "Fix available"; a fix that ' +
      "needs Ubuntu Pro doesn't count)",
  );
